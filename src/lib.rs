//! prospi 共用核心：行程記憶體存取、選手物件解析、球種表、原創球種記錄。
//!
//! 完全不用外部 crate 做 Win32 存取，直接 FFI kernel32。
#![allow(non_snake_case, non_camel_case_types)]

use std::collections::HashSet;

use std::ffi::c_void;

pub const PROC_NAME: &str = "prospi-Win64-Shipping.exe";

// ─────────────────────────────────────────────── Win32 FFI

type HANDLE = *mut c_void;
type BOOL = i32;

const TH32CS_SNAPPROCESS: u32 = 0x2;
const TH32CS_SNAPMODULE: u32 = 0x8;
const TH32CS_SNAPMODULE32: u32 = 0x10;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PROCESS_QUERY_INFORMATION: u32 = 0x400;
const PROCESS_VM_READ: u32 = 0x10;
const PROCESS_VM_WRITE: u32 = 0x20;
const PROCESS_VM_OPERATION: u32 = 0x8;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MEMORY_BASIC_INFORMATION {
    BaseAddress: usize,
    AllocationBase: usize,
    AllocationProtect: u32,
    __a1: u32,
    RegionSize: usize,
    State: u32,
    Protect: u32,
    Type: u32,
    __a2: u32,
}

#[repr(C)]
struct PROCESSENTRY32W {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [u16; 260],
}

#[repr(C)]
struct MODULEENTRY32W {
    dwSize: u32,
    th32ModuleID: u32,
    th32ProcessID: u32,
    GlblcntUsage: u32,
    ProccntUsage: u32,
    modBaseAddr: usize,
    modBaseSize: u32,
    hModule: usize,
    szModule: [u16; 256],
    szExePath: [u16; 260],
}

extern "system" {
    fn CreateToolhelp32Snapshot(f: u32, pid: u32) -> HANDLE;
    fn Process32FirstW(h: HANDLE, e: *mut PROCESSENTRY32W) -> BOOL;
    fn Process32NextW(h: HANDLE, e: *mut PROCESSENTRY32W) -> BOOL;
    fn Module32FirstW(h: HANDLE, e: *mut MODULEENTRY32W) -> BOOL;
    fn Module32NextW(h: HANDLE, e: *mut MODULEENTRY32W) -> BOOL;
    fn OpenProcess(a: u32, i: BOOL, pid: u32) -> HANDLE;
    fn CloseHandle(h: HANDLE) -> BOOL;
    fn VirtualQueryEx(h: HANDLE, a: *const c_void, b: *mut MEMORY_BASIC_INFORMATION,
                      l: usize) -> usize;
    fn VirtualAllocEx(h: HANDLE, a: *mut c_void, s: usize, typ: u32, protect: u32) -> *mut c_void;
    fn VirtualFreeEx(h: HANDLE, a: *mut c_void, s: usize, typ: u32) -> BOOL;
    fn ReadProcessMemory(h: HANDLE, a: *const c_void, b: *mut c_void, s: usize,
                         r: *mut usize) -> BOOL;
    fn WriteProcessMemory(h: HANDLE, a: *mut c_void, b: *const c_void, s: usize,
                          w: *mut usize) -> BOOL;
    fn VirtualProtectEx(h: HANDLE, a: *mut c_void, s: usize, new: u32, old: *mut u32) -> BOOL;
}

fn wide_to_string(w: &[u16]) -> String {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..n])
}

pub fn find_pid(name: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap as isize == -1 {
            return None;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let want = name.to_lowercase();
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            if wide_to_string(&e.szExeFile).to_lowercase() == want {
                let pid = e.th32ProcessID;
                CloseHandle(snap);
                return Some(pid);
            }
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
        None
    }
}

pub struct Proc {
    h: HANDLE,
    pub pid: u32,
    pub base: usize,
}

unsafe impl Send for Proc {}
unsafe impl Sync for Proc {}

impl Proc {
    /// 附加到遊戲行程（讀＋寫）。Denuvo 不擋外部 RPM/WPM，免管理員。
    pub fn attach() -> Result<Proc, String> {
        let pid = find_pid(PROC_NAME).ok_or_else(|| format!("找不到行程 {PROC_NAME}"))?;
        let h = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION,
                0,
                pid,
            )
        };
        if h.is_null() {
            return Err(format!("OpenProcess 失敗 (pid {pid})"));
        }
        let base = module_base(pid, PROC_NAME).unwrap_or(0);
        Ok(Proc { h, pid, base })
    }

    pub fn read(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut got = 0usize;
        let ok = unsafe {
            ReadProcessMemory(self.h, addr as *const c_void,
                              buf.as_mut_ptr() as *mut c_void, len, &mut got)
        };
        if ok == 0 || got == 0 {
            return None;
        }
        buf.truncate(got);
        Some(buf)
    }

    pub fn write(&self, addr: usize, data: &[u8]) -> bool {
        let mut done = 0usize;
        let ok = unsafe {
            WriteProcessMemory(self.h, addr as *mut c_void,
                               data.as_ptr() as *const c_void, data.len(), &mut done)
        };
        ok != 0 && done == data.len()
    }

    pub fn u8_at(&self, a: usize) -> u8 { self.read(a, 1).map_or(0, |b| b[0]) }

    pub fn u16_at(&self, a: usize) -> u16 {
        self.read(a, 2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32_at(&self, a: usize) -> u32 {
        self.read(a, 4).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64_at(&self, a: usize) -> u64 {
        self.read(a, 8).map_or(0, |b| {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        })
    }

    pub fn regions(&self) -> Vec<(usize, usize, u32, u32)> {
        let mut out = Vec::new();
        let mut addr = 0usize;
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let sz = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        unsafe {
            while VirtualQueryEx(self.h, addr as *const c_void, &mut mbi, sz) == sz {
                let next = mbi.BaseAddress.wrapping_add(mbi.RegionSize);
                if next <= addr {
                    break;
                }
                if mbi.State == MEM_COMMIT {
                    out.push((mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type));
                }
                addr = next;
                if addr > 0x7FFF_FFFF_FFFF {
                    break;
                }
            }
        }
        out
    }

    pub fn writable_ranges(&self) -> Vec<(usize, usize)> {
        self.regions()
            .into_iter()
            .filter(|&(_, _, p, _)| writable(p))
            .map(|(b, s, _, _)| (b, s))
            .collect()
    }

    /// **可執行**區段（程式碼）。找 AOB 樣式的指令時要用這個 ——
    /// `writable_ranges()` 會把 `PAGE_EXECUTE_READ`(0x20) 濾掉，
    /// 所以拿它掃指令一定是 0 命中（2026-08-01 踩到：CT 的道具 AOB 掃不出來，
    /// 不是版本偏移，是**根本沒掃程式碼段**）。
    pub fn exec_ranges(&self) -> Vec<(usize, usize)> {
        self.regions()
            .into_iter()
            .filter(|&(_, _, p, _)| executable(p))
            .map(|(b, s, _, _)| (b, s))
            .collect()
    }

    /// 寫入**程式碼段**。程式碼是 `PAGE_EXECUTE_READ`（唯讀），直接 `write()` 一定失敗 ——
    /// 要先 `VirtualProtectEx` 開權限、寫完再改回原本的保護屬性。
    ///
    /// ⚠ runtime code patch 比改資料危險：位址算錯就是改到別的指令。
    /// **一律用 `aobcode` 找到位址再寫，不要寫死**（程式碼位址會隨版本偏移）。
    pub fn write_code(&self, addr: usize, data: &[u8]) -> bool {
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        let mut old = 0u32;
        unsafe {
            if VirtualProtectEx(self.h, addr as *mut c_void, data.len(),
                                PAGE_EXECUTE_READWRITE, &mut old) == 0 {
                return false;
            }
        }
        let ok = self.write(addr, data);
        let mut back = 0u32;
        unsafe {
            VirtualProtectEx(self.h, addr as *mut c_void, data.len(), old, &mut back);
        }
        ok
    }
}

// ─────────────────────────────────────────────── 上限 patch（明星選手）

/// 球速上限 175 寫死在 `exe+594A4C0: mov ecx,0xAF`（`cmovg eax,ecx` 夾住）。
/// 編碼是 `raw = (球速 + 0x30) & 0x7F`、顯示 `= raw + 80`，而 `+48 ≡ −80 (mod 128)`，
/// 所以**資料結構本身能到 207**（7 bits 上限 127 + 80）—— 175 純粹是程式碼限制。
pub const SPEED_CAP_AOB: &str = "b9 ?? 00 00 00 3b d8 0f 4d c3";
/// ★ 球速上限的**第二處**（換算完先夾一次）。只改 setter 那處不會生效。
pub const SPEED_CAP_AOB2: &str = "bd ?? 00 00 00 44 3b fd 44 0f 4f fd";
pub const SPEED_CAP_MAX: u8 = 207;
/// 能力值上限 99 寫死在 `exe+62A7AAD: mov eax,0x63`（換算函式最後 `cmovg edi,eax`）。
pub const STAT_CAP_AOB: &str = "b8 ?? 00 00 00 0f 49 fd";

/// 道具「使用次數」的 `inc al`（`exe+5B957A1`，緊接著就是 `mov [rcx+rdi],al`）。
///
/// 把它 nop 掉 ＝ 計數器永遠停在 0 ＝ **使用次數永遠不增加 ＝ 無限使用**。
///
/// 為什麼不改資料：陣列基址是呼叫端傳進來的參數（實測 `RDI=0xD9303028`），
/// **跟主角物件沒有固定位移**（物件搬家後推算 `−0x3A8` 讀到的是別的東西），
/// 舊記錄的靜態指標 `[exe+195FC798]` 實測也是 0。
/// 相較之下這條指令用 AOB 一定找得到，而且不受物件搬家影響。
///
/// ⚠ 這是**通用計數器**（`cmp ebx,0x110` ＝ index 夾在 0..271），
/// nop 掉會讓所有走這條路的計數都不增加，不只道具。實測不會崩潰，只是數字不動。
/// AOB 用萬用位元組寫前兩個 byte，**patch 後仍找得到**。
pub const ITEM_INC_AOB: &str = "?? ?? 88 04 39 48 8b 5c 24 30";

/// 在**程式碼段**找一段樣式（`??` ＝ 萬用位元組），回傳第一個命中位址。
pub fn find_code(p: &Proc, pat_str: &str) -> Option<usize> {
    const CHUNK: usize = 64 << 20;
    let pat: Vec<Option<u8>> = pat_str
        .split_whitespace()
        .map(|t| if t.starts_with('?') { None } else { u8::from_str_radix(t, 16).ok() })
        .collect();
    for (b, sz) in p.exec_ranges() {
        let mut off = 0usize;
        while off < sz {
            let n = (sz - off).min(CHUNK + pat.len());
            if let Some(buf) = p.read(b + off, n) {
                if buf.len() >= pat.len() {
                    for q in 0..=buf.len() - pat.len() {
                        if pat.iter().enumerate().all(|(i, x)| x.map_or(true, |v| buf[q + i] == v)) {
                            return Some(b + off + q);
                        }
                    }
                }
            }
            off += CHUNK;
        }
    }
    None
}

/// 同 `find_code`，但回傳**所有**命中位址。
///
/// 定位 singleton getter 時必須用這個 —— `mov rax,[rip+X]/mov rax,[rax+0x70]`
/// 這種通用樣式在程式碼段會有數個命中（實測 2 個），
/// 只取第一個會挑到別的 getter。
pub fn find_code_all(p: &Proc, pat_str: &str) -> Vec<usize> {
    const CHUNK: usize = 64 << 20;
    let pat: Vec<Option<u8>> = pat_str
        .split_whitespace()
        .map(|t| if t.starts_with('?') { None } else { u8::from_str_radix(t, 16).ok() })
        .collect();
    let mut out = Vec::new();
    if pat.is_empty() {
        return out;
    }
    for (b, sz) in p.exec_ranges() {
        let mut off = 0usize;
        while off < sz {
            let n = (sz - off).min(CHUNK + pat.len());
            if let Some(buf) = p.read(b + off, n) {
                if buf.len() >= pat.len() {
                    for q in 0..=buf.len() - pat.len() {
                        if pat.iter().enumerate().all(|(i, x)| x.map_or(true, |v| buf[q + i] == v)) {
                            out.push(b + off + q);
                        }
                    }
                }
            }
            off += CHUNK;
        }
    }
    out
}

/// 道具使用次數是否已被 nop（＝無限使用）
pub fn item_use_patched(p: &Proc) -> Option<bool> {
    let a = find_code(p, ITEM_INC_AOB)?;
    Some(p.read(a, 2)? == [0x90, 0x90])
}

/// 開/關「道具使用不消耗」。nop 掉 `inc al` ＝ 計數器永遠 0。
///
/// ⚠ 這是 code patch，不是持續重寫 —— **按一次就好，不需要背景執行緒**。
/// 遊戲重開後 patch 會消失（記憶體修改不進 exe），要重按。
pub fn set_item_use_patch(p: &Proc, on: bool) -> bool {
    match find_code(p, ITEM_INC_AOB) {
        Some(a) => p.write_code(a, if on { &[0x90, 0x90] } else { &[0xFE, 0xC0] }),
        None => false,
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.h) };
    }
}

pub fn module_base(pid: u32, name: &str) -> Option<usize> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap.is_null() || snap as isize == -1 {
            return None;
        }
        let mut e: MODULEENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        let want = name.to_lowercase();
        let mut ok = Module32FirstW(snap, &mut e);
        while ok != 0 {
            if wide_to_string(&e.szModule).to_lowercase() == want {
                let b = e.modBaseAddr;
                CloseHandle(snap);
                return Some(b);
            }
            ok = Module32NextW(snap, &mut e);
        }
        CloseHandle(snap);
        None
    }
}

/// ⚠ 只比對 Protect 的低位元組。這款有 0x404（PAGE_READWRITE + CFG）的 4.4GB 區段，
/// 寫成 `p == 0x04 || p == 0x40` 會漏掉一半以上的記憶體。
pub fn writable(prot: u32) -> bool {
    matches!(prot & 0xFF, 0x04 | 0x08 | 0x40 | 0x80) && (prot & 0x100) == 0
}

/// 可執行（程式碼）。同樣只看低位元組，並排除 PAGE_GUARD。
/// `0x10` EXECUTE、`0x20` EXECUTE_READ、`0x40` EXECUTE_READWRITE、`0x80` EXECUTE_WRITECOPY。
pub fn executable(prot: u32) -> bool {
    matches!(prot & 0xFF, 0x10 | 0x20 | 0x40 | 0x80) && (prot & 0x100) == 0
}

// ─────────────────────────────────────────────── 球種表

/// 球種 ID 全域唯一，名稱只由 ID 決定，跟放在哪個方向無關（2026-07-26 實測確認）。
/// BALL_DIR 是「本來屬於哪個方向」的語意規則，不是遊戲的硬限制。
pub const BALL_EMPTY: u8 = 37;
pub const BALL_ORIGINAL: u8 = 36;
pub const N_BALL: usize = 12;

pub const BALL_NAMES: &[(u8, &str)] = &[
    (0, "直球"), (1, "飄移快速球"), (2, "二縫線快速球"), (3, "慢速直球"),
    (4, "滑球"), (5, "高速滑球"), (6, "卡特球"), (7, "慢速滑球"),
    (8, "曲球"), (9, "慢速曲球"), (10, "垂直曲球"), (11, "滑曲球"),
    (12, "超慢速曲球"), (13, "彈指曲球"),
    (14, "指叉球"), (15, "掌心球"), (16, "蝴蝶球"), (17, "縱向滑球"),
    (18, "變速球"), (19, "快速指叉球"), (20, "縱向卡特球"), (21, "滑行掌心球"),
    (22, "慢速變速球"),
    (23, "伸卡球"), (24, "螺旋球"), (25, "高速伸卡球"), (26, "高速螺旋球"),
    (27, "慢速伸卡球"), (28, "慢速螺旋球"), (29, "超高速伸卡球"),
    (30, "超高速螺旋球"), (31, "圈指變速球"), (32, "慢速圈指變速球"),
    (33, "噴射球"), (34, "高速噴射球"), (35, "快速下沉球"),
    (36, "原創球種"),
    (38, "真滑球"), (39, "自然噴射球"), (40, "慢速魔球"),
    (41, "強力曲球"), (42, "螺旋指叉球"), (43, "變速指叉球"),
];

/// ID 是按方向分段配置的（(起, 迄, 方向)）
const BALL_DIR_RANGES: &[(u8, u8, usize)] = &[
    (0, 3, 5), (4, 7, 0), (8, 13, 1), (14, 22, 2),
    (23, 32, 3), (33, 35, 4), (38, 40, 5),
    (41, 41, 1), (42, 42, 2), (43, 43, 3),
];

pub fn ball_dir(id: u8) -> Option<usize> {
    BALL_DIR_RANGES.iter().find(|r| id >= r.0 && id <= r.1).map(|r| r.2)
}

pub fn ball_name(id: u8) -> String {
    if id == BALL_EMPTY {
        return "－（空）".into();
    }
    BALL_NAMES
        .iter()
        .find(|e| e.0 == id)
        .map(|e| e.1.to_string())
        .unwrap_or_else(|| format!("★未知 ID{id}"))
}

/// 某方向可選的球種（給下拉選單用）：空、原創、再加上該方向的正規球種
pub fn balls_for_dir(dir: usize) -> Vec<u8> {
    let mut v = vec![BALL_EMPTY, BALL_ORIGINAL];
    for &(id, _) in BALL_NAMES {
        if id != BALL_ORIGINAL && ball_dir(id) == Some(dir) {
            v.push(id);
        }
    }
    v
}

/// 原創球種名稱的日文→中文對照。
/// ⚠ 這是為了看得懂而加的翻譯，**不是遊戲官方譯名** ——
/// 記錄裡存什麼字串，遊戲畫面就顯示什麼字串，所以 UI 要把原文一起帶著。
pub const JP_ZH: &[(&str, &str)] = &[
    ("カットボール", "卡特球"), ("スイーパー", "橫掃球"), ("スライダー", "滑球"),
    ("ライズカット", "上飄卡特"), ("高速スライダー", "高速滑球"),
    ("縦スライダー", "縱向滑球"),
    ("カーブ", "曲球"), ("高速カーブ", "高速曲球"), ("ナックルカーブ", "彈指曲球"),
    ("マッスルカーブ", "肌肉曲球"), ("オージーカーブ", "OG曲球"),
    ("カツオカーブ", "鰹魚曲球"), ("ジェッスラ", "噴射滑球"), ("スローボール", "慢速球"),
    ("フォーク", "指叉球"), ("フォースラ", "指叉滑球"), ("フォーチェ", "指叉變速"),
    ("ＳＦＦ", "SFF快速指叉"), ("パーム", "掌心球"),
    ("ジャイロスプリット", "螺旋指叉"), ("ジャイロスライダー", "螺旋滑球"),
    ("スプリンカー", "指叉伸卡"), ("河野ボール", "河野球"),
    ("チェンジアップ", "變速球"), ("スプリット", "分指球"),
    ("スプリットチェンジ", "分指變速"), ("スプリーム", "至尊球"),
    ("シンカー", "伸卡球"), ("ツーシーム", "二縫線"), ("ワンシーム", "一縫線"),
    ("こやシン", "小屋伸卡"), ("ツーシームファスト", "二縫線快速球"),
    ("ストレート", "直球"), ("マッスルストレート", "肌肉直球"),
    ("火の玉ストレート", "火球直球"),
];

/// 中文在前、原文在後（原文才是遊戲畫面實際會顯示的字串）
pub fn zh_name(n: &str) -> String {
    match JP_ZH.iter().find(|e| e.0 == n) {
        Some(e) => format!("{}（{}）", e.1, n),
        None => n.to_string(),
    }
}

pub const LEVELS: [&str; 8] = ["G", "F", "E", "D", "C", "B", "A", "S"];

pub fn lv(n: u8) -> &'static str {
    *LEVELS.get(n as usize).unwrap_or(&"?")
}

/// 球種系統名 —— パワプロ／プロスピ 官方就是把變化球分成這 6 系
/// （ストレート系・スライダー系・カーブ系・フォーク系・シンカー系・シュート系）。
/// 我們的「方向 0~5」其實就是這 6 系，而且 **ID 分段順序 ＝ 官方系統順序**：
/// `0-3 直球系 → 4-7 滑球系 → 8-13 曲球系 → 14-22 指叉球系 → 23-32 伸卡球系 → 33-35 噴射球系`。
/// UI 一律顯示系統名，不要顯示內部的「方向N」。
pub const DIR_SERIES: [&str; 6] = [
    "滑球系", "曲球系", "指叉球系", "伸卡球系", "噴射球系", "直球系",
];

/// 各系在遊戲的放射狀球種圖上落在哪個位置（左右投手會鏡像對調）
pub const DIR_UI: [&str; 6] = [
    "右投左 / 左投右",
    "右投左下 / 左投右下",
    "下",
    "右投右下 / 左投左下",
    "右投右 / 左投左",
    "上",
];

/// UI 的顯示順序 ＝ 官方系統順序（直球系排最前面，跟球種 ID 分段一致）
pub const DIR_ORDER: [usize; 6] = [5, 0, 1, 2, 3, 4];

// ─────────────────────────────────────────────── 選手物件

pub const OFF_ABIL2: usize = 0x08;
pub const OFF_STATS: usize = 0x20;
pub const OFF_DEF: usize = 0x28;
pub const OFF_PACK: usize = 0x29;
pub const OFF_BALL: usize = 0x30;
pub const OFF_ORIG: usize = 0x54;
pub const OFF_NAME: usize = 0x914;
pub const OFF_GRADE: usize = 0xE50;
/// 栄冠球員信賴度（0..=0xC8 / 0..=200）
pub const OFF_TRUST: usize = 0xE80;
/// 栄冠球員個性 ID（0x00..0x07）
pub const OFF_PERSONALITY: usize = 0xE81;
/// 栄冠球員情緒 ID（0=超興奮, 1=興奮, 2=普通, 3=消沉）
pub const OFF_MOOD: usize = 0xE82;
/// 栄冠球員體力（u16 little-endian，0..=0x01F4 / 0..=500）
pub const OFF_ENERGY: usize = 0xE86;
/// 栄冠球員學力實際值（u8）。
/// 2026-08-30 重新以正確 Player Object 做差分與因果驗證，確認 +0xE88 會直接影響學力顯示。
/// 已實測 Rank 區間：E=0x00..0x23、D=0x24..0x2D、C=0x2E..0x37、
/// B=0x38..0x41、A=0x42..0x4B。
/// ⚠ 先前判定「+0xE88 無效」是因為測到錯誤的球員 / Player Object；目前恢復為可寫欄位。
pub const OFF_ACADEMIC: usize = 0xE88;
/// 栄冠球員招募評價（u16 little-endian，0..=0x01FF / 0..=511）
pub const OFF_RECRUIT_EVAL: usize = 0xE8C;
pub const OFF_ITEM: usize = 0x1511;
pub const OFF_BOOK: usize = 0x1512;

pub const REC: usize = 0xB8;
pub const N_REC: usize = 12;
pub const REC_SLOT: usize = 0x00;
pub const REC_NAME: usize = 0x04;
pub const REC_NAME_MAX: usize = 0x64;
pub const REC_KANA: usize = 0x68;
pub const REC_OFFICIAL: usize = 0x91;
pub const REC_BASE: usize = 0xB4;
pub const REC_UNUSED_SLOT: u32 = 12;

// ── 特殊能力：+0x08..0x15 = 14 bytes = 28 個 nibble，一個 nibble ＝ 一個能力欄位。
//    等級 ＝ 低 3 bits 的「以 D 為 0 的 signed」；bit3 是另一個旗標（意義未明）。
//    ⚠ 值 4（＝ signed −4）超出等級表 → 空白條目 → **遊戲會當掉**，絕對不要寫。
pub const ABIL_OFF: usize = OFF_ABIL2;
pub const ABIL_BYTES: usize = 14;
pub const ABIL_NIBBLES: usize = ABIL_BYTES * 2;
pub const ABIL_LEVELS: [&str; 8] = ["D", "C", "B", "A", "⚠無效", "G", "F", "E"];

/// 等級類欄位的名稱（值 ＝ D/C/B/A…，見 ABIL_GRADED）
pub const ABIL_KNOWN: &[(usize, &str)] = &[
    (0, "短打"), (1, "得分機會"), (2, "犀利度"), (3, "尾勁"),
    (4, "對危機"), (5, "快速投球"),
    (6, "抗壓性"), (7, "對左打者"), (8, "跑壘"), (9, "盜壘"), (10, "抗傷能力"),
];

/// **等級格的 bit3 各自帶一個獨立能力** —— 所以等級 nibble ＝「低3bit 等級 ＋ bit3 附加能力」。
/// (nibble, 能力名)
pub const ABIL_GRADED_BIT3: &[(usize, &str)] = &[
    (0, "巧打型打者"), (1, "壞球追擊"), (2, "高速擊球"), (3, "機會創造者"),
    (4, "界外球纏鬥"), (5, "代打"),
    (6, "逆境"), (7, "觸身球"), (8, "出人意料"), (9, "安打高手"), (10, "滿壘男"),
];

/// 等級格分兩種，差別只在「等級 0」怎麼顯示：
/// * **必顯示型**（其餘 9 格）：等級 0 ＝ 畫面上的 **D**，每位選手一定看得到這 9 項。
/// * **選配型**（`n2` 犀利度、`n3` 尾勁）：等級 0 ＝ **沒有這個能力**，畫面上不出現。
///
/// 這解釋了為什麼寫 `n2=8`／`n3=8` 時只出現 bit3 的能力（高速擊球／機會創造者），
/// 也解釋了把 9 個必顯示格歸零後畫面剛好只剩 9 個 D。
pub const ABIL_GRADED_OPTIONAL: &[usize] = &[2, 3];

/// ★★★ 變體格 ＝ **4 個獨立 bit**，每個 bit 一個能力。
/// bit0/bit1 成一對、bit2/bit3 成一對，**同一對的兩個 bit 同時設定時的顯示規則**：
///
/// * 兩者是**同一特性的不同版本**（○/✕、基本/強化）→ **互斥，畫面只畫較高的那個 bit**
///   （`n16=3` 只顯示滾地球型投手、`n16=12` 只顯示援護▼、`n11=12` 只顯示對直球○）
/// * 兩者是**不相關的能力** → **兩個都顯示**
///   （`n26=3` ＝ 藏球＋力量分配、`n23=12` ＝ 推打＋再見英雄、`n17=6` ＝ 威壓感＋牽制○）
///
/// 2026-07-26 曾誤判成「2 個 2-bit 欄位、值 1/2/3 是三個版本」，因為當時測的值
/// 剛好全是互斥組合、每個都只顯示一個能力。`n26=3` 一次給出兩個不相關能力才推翻它。
///
/// ⚠ **圖示顏色不是「正面/負面」**：粉紅只是一般樣式，負面能力的**輕微版也是粉紅**
/// （`n18=4` 的「動搖」是粉紅，HELP 仍寫「稍微有狀況就會影響投球的穩定度」）。
/// 正確讀法：**同一對的低 bit ＝ 粉紅(輕)、高 bit ＝ 紫色(重)**，名稱與 HELP 完全相同；
/// 金色 ＝ 稀有/強力、半紫（斜切）＝ 有利有弊。
/// `n18`/`n20`/`n21`/`n22` 這四對就是純粹的輕/重兩版，`n15` bit2/bit3 也都叫「拉鋸戰」。
///
/// (nibble, bit, 能力名)
pub const ABIL_BITS: &[(usize, u8, &str)] = &[
    // ⚠ n2/n3 已改歸類為「等級格」（犀利度／尾勁），不在這張變體表裡 —— 見 ABIL_GRADED。
    (11, 0, "致勝一擊"), (11, 1, "全力的致勝一擊"),
    (11, 2, "對變化球○"), (11, 3, "對直球○"),
    (12, 0, "存在感"), (12, 1, "威壓感[野手]"),
    (12, 2, "廣角打法"), (12, 3, "拉打型打者"),
    (13, 0, "纏鬥"), (13, 1, "三振"),
    (13, 2, "連續開轟"), (13, 3, "再來一發"),
    (14, 0, "擊球反應○"), (14, 1, "擊球反應▼"),
    (14, 2, "短打衝刺○"), (14, 3, "短打衝刺▼"),
    (15, 0, "雷射肩"), (15, 1, "高速雷射肩"),
    (15, 2, "拉鋸戰"), (15, 3, "拉鋸戰✕"),
    (16, 0, "飛球型投手"), (16, 1, "滾地球型投手"),
    (16, 2, "援護○"), (16, 3, "援護✕"),
    (17, 0, "存在感"), (17, 1, "威壓感[投手]"),
    (17, 2, "牽制○"), (17, 3, "牽制◎"),
    // ⚠ n18/n20/n21/n22 的這幾對是**同一個負面能力的輕/重兩版**：
    // 名稱與 HELP 說明完全相同，只有圖示顏色不同（低 bit ＝ 粉紅輕微、高 bit ＝ 紫色嚴重）。
    (18, 0, "逃遁球"), (18, 1, "容易挨轟"),
    (18, 2, "動搖(輕)"), (18, 3, "動搖(重)"),
    (19, 0, "出手"), (19, 1, "狂野球"),
    (19, 2, "對跑者○"), (19, 3, "對跑者✕"),
    (20, 0, "四壞球(輕)"), (20, 1, "四壞球(重)"),
    (20, 2, "噴射球旋轉(輕)"), (20, 3, "噴射球旋轉(重)"),
    (21, 0, "慢熱型(輕)"), (21, 1, "慢熱型(重)"),
    (21, 2, "球速穩定○"), (21, 3, "球速穩定✕"),
    (22, 0, "近勝情怯(輕)"), (22, 1, "近勝情怯(重)"),
    (22, 2, "內野安打○"), (22, 3, "內野安打✕"),
    (23, 0, "午場比賽"), (23, 1, "晚場比賽"),
    (23, 2, "推打"), (23, 3, "再見英雄"),
    (24, 0, "第一球"), (24, 1, "死守本壘"),
    (24, 2, "守備職人"), (24, 3, "奪三振"),
    // ⚠ bit0 舊記為「逃遁球」是從粗略記錄繼承的誤植；`n25=3` 實測是「變換檔位＋攻擊內角」。
    // 真正的逃遁球在 n18 bit0（第 5 輪金村身上單獨驗證）。
    (25, 0, "變換檔位"), (25, 1, "攻擊內角"),
    (25, 2, "緊急登板○"), (25, 3, "漸入佳境"),
    (26, 0, "藏球"), (26, 1, "力量分配"),
    (26, 2, "頭部滑壘"), (26, 3, "神之手"),
    (27, 0, "盜壘頭部滑壘"), (27, 1, "衝回本壘"),
    (27, 2, "大場面"), (27, 3, "哥吉拉"),
];

/// 變體格：把設定的每個 bit 翻成能力名（未知的標成 `bitN?`）。
/// ⚠ 畫面上同一對若是正負版本會互斥只顯示一個，這裡一律全列出來。
pub fn abil_variant_desc(n: usize, v: u8) -> String {
    let mut out = Vec::new();
    for b in 0..4u8 {
        if v >> b & 1 == 0 {
            continue;
        }
        match ABIL_BITS.iter().find(|e| e.0 == n && e.1 == b) {
            Some(e) => out.push(e.2.to_string()),
            None => out.push(format!("bit{b}?")),
        }
    }
    if out.is_empty() { "－".into() } else { out.join(" + ") }
}

/// 某個變體格還沒解出的 bit —— 規劃下一輪實驗用
pub fn abil_missing(n: usize) -> Vec<u8> {
    (0..4u8).filter(|&b| !ABIL_BITS.iter().any(|e| e.0 == n && e.1 == b)).collect()
}

/// 曾以為沒使用的 nibble —— **已推翻**。栄冠 25 位部員身上恰好全是 0，
/// 但明星選手模式掃到的 1467 位官方選手裡 `n18` 有 532 位、`n20` 有 276 位、`n14` 有 210 位。
/// **小樣本的「全 0」只代表沒觀察到，不代表欄位不存在。**
pub const ABIL_UNUSED: &[usize] = &[];

/// 每個 nibble **實際觀察過**的 bit ＝ 25 位真實部員出現過的值 ∪ 已實測寫入不當機的 bit。
/// 某個 bit 為 0 ＝ 這格的這個 bit 從沒見過 → 該能力欄位可能根本沒定義，寫進去會當掉。
///
/// ⚠ 2026-07-26 實測代價：以為「變體格的 4 一定合法」，對 `n2`/`n3`/`n15`/`n25`
/// 寫了沒有觀察值的 bit2，**遊戲直接崩潰**。
/// 等級格只檢查 bit3（低 3 bit 是等級值，另由 `abil_is_graded` 那條擋 4）。
/// 每格**完整觀察過的值**（樣本 ＝ 1466 位官方選手 ∪ 25 位栄冠部員）。
/// bit v 為 1 ＝ 該格出現過值 v。值 0 一律合法。
///
/// ⚠⚠ **必須用「值」而不是「bit」當白名單** —— 2026-07-26 用 bit 層級擋，
/// 判定 `n3 bit2` 有觀察值（因為 5 位選手的 `n3 = 7 = bit0|bit1|bit2`）而放行，
/// 單獨寫 `n3 = 4` 當場崩潰。**`n17=6` 同時給出威壓感＋牽制○ 證明 `n17` 是 bit flags，
/// 但那不能推廣到每一格；`n3` 的值顯然是整體索引。**
/// 每格的語意各自不同，唯一保證安全的是「照抄真實選手身上出現過的完整值」。
///
/// ※ `n10` 的值 4 只出現在 1 位（疑似掃描假陽性）且等級格的 4 ＝ signed −4，已剔除。
pub const ABIL_SEEN_VALS: [u16; ABIL_NIBBLES] = [
    // n2/n3 的 1/2/3/5/6/7 是 2026-07-26 實測補上的（真實選手只出現過 7 和 8）：
    // 六個值全部安全，顏色也對上等級表（A/B/C 粉紅、E/F/G 紫）。只有 4（＝−4）會崩。
    0x03EF, 0x8BCF, 0x01EF, 0x01EF,  // n0..n3
    0x01CF, 0x81EF, 0x01CF, 0x01CF,  // n4..n7
    0x038F, 0xCFCF, 0x01EF, 0x5157,  // n8..n11
    0xD05F, 0x93BB, 0x903B, 0x101F,  // n12..n15
    0xB0BB, 0x0317, 0xB10B, 0xB0FF,  // n16..n19
    0x900B, 0x9099, 0x1019, 0x311B,  // n20..n23
    0x0337, 0x1FFF, 0x111F, 0x00DD,  // n24..n27
];

/// 等級由高到低：A B C D E F G（值 3/2/1/0/7/6/5）
pub const GRADE_ORDER: [u8; 7] = [3, 2, 1, 0, 7, 6, 5];

/// 寫入本地緩衝的單一 nibble
pub fn set_nib_buf(b: &mut [u8], n: usize, v: u8) {
    let i = n / 2;
    b[i] = if n % 2 == 0 { (b[i] & 0xF0) | (v & 0xF) } else { (b[i] & 0x0F) | (v << 4) };
}

/// 把 11 個等級格拉到「觀察過的最高等級」，**保留各格的 bit3 附加能力**。
///
/// 為什麼要這個：等級（低 3 bits）與 bit3 附加能力**擠在同一個 nibble**，
/// 而遊戲的等級升級是整個 nibble 重寫 —— 所以升一次級就會把同格的 bit3 洗掉
/// （＝使用者說的「學新技能後被重置」）。**拉到最高就不會再升級**，bit3 也就保得住。
///
/// ⚠ 不能無腦寫 `bit3|3`：`n9=0xB` 在 1491 位樣本裡有，但 `n0=0xB` 沒有 ——
/// 沒觀察過的值會讓遊戲當掉（本專案崩過三次）。所以逐格從 A 往下找第一個合法值。
/// 選配型（`n2` 犀利度／`n3` 尾勁）等級 0 ＝ 沒有該能力，**不無中生有**。
pub fn max_abil_grades(p: &Proc, obj: usize) -> Option<usize> {
    let mut b = p.read(obj + ABIL_OFF, ABIL_BYTES)?;
    let mut n_changed = 0;
    for &n in ABIL_GRADED {
        let cur = abil_nib(&b, n);
        if ABIL_GRADED_OPTIONAL.contains(&n) && cur & 7 == 0 && cur & 8 == 0 {
            continue; // 這格本來就沒有能力, 別無中生有
        }
        let bit3 = cur & 8;
        let legal = abil_legal_vals(n);
        for &g in GRADE_ORDER.iter() {
            let want = bit3 | g;
            if want == cur {
                break; // 已經是最高的合法等級了
            }
            if want == 0 || legal.contains(&want) {
                set_nib_buf(&mut b, n, want);
                n_changed += 1;
                break;
            }
        }
    }
    p.write(obj + ABIL_OFF, &b).then_some(n_changed)
}

/// 該格觀察過的值清單（供錯誤訊息與編輯器選單用）
pub fn abil_legal_vals(n: usize) -> Vec<u8> {
    (1..16u8).filter(|&v| ABIL_SEEN_VALS[n] >> v & 1 == 1).collect()
}

/// 列出一組 14 bytes 裡「從未觀察過的值」——寫入前的安全檢查。回傳 (nibble, 值)。
pub fn abil_illegal_vals(v: &[u8]) -> Vec<(usize, u8)> {
    abil_nibbles(v).iter().enumerate()
        .filter(|&(i, &x)| ABIL_SEEN_VALS[i] >> x & 1 == 0)
        .map(|(i, &x)| (i, x))
        .collect()
}

/// 等級類欄位（值 ＝ 以 D 為 0 的 signed 3-bit）。
/// **只有這些位置寫入 4（＝−4）會超出等級表而當掉**；
/// 其餘欄位的 4 是合法的變體編號（真實部員身上就有）。
/// ⚠ `n2`/`n3` 是 2026-07-26 才確認的等級格（犀利度／尾勁），
/// 證據：`n3=1→C 2→B 7→E`（同名、等級低變紫色）且 **`n2=4`/`n3=4` 單獨寫入必崩**（signed −4）。
pub const ABIL_GRADED: &[usize] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

pub fn abil_is_graded(n: usize) -> bool {
    ABIL_GRADED.contains(&n)
}

pub fn abil_name(n: usize) -> &'static str {
    ABIL_KNOWN.iter().find(|e| e.0 == n).map(|e| e.1).unwrap_or("（未確認）")
}

pub fn abil_level(v: u8) -> &'static str {
    ABIL_LEVELS[(v & 7) as usize]
}

/// 把 14 bytes 拆成 28 個 nibble（低 nibble 在前）
pub fn abil_nibbles(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ABIL_NIBBLES);
    for &x in b.iter().take(ABIL_BYTES) {
        v.push(x & 0xF);
        v.push(x >> 4);
    }
    v
}

pub const STAT_NAMES: [&str; 8] = [
    "對右打擊", "對左打擊", "力量", "速度", "臂力", "傳球", "接球", "疲勞消除",
];

#[derive(Clone, Debug, Default)]
pub struct Ball {
    pub id: u8,
    pub power: u8,
    pub control: u8,
    pub move_: u8,
}

#[derive(Clone, Debug, Default)]
pub struct OrigRec {
    pub slot: u32,
    pub name: String,
    pub base: u8,
    pub official: bool,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Player {
    pub addr: usize,
    pub name: String,
    pub stats: [u8; 8],
    /// `+0x18..0x1F` 的 8 個野手守位適性：捕/一/二/三/遊/左/中/右
    pub field: [u8; 8],
    /// `+0x28` 投手適性
    pub defense: u8,
    /// `+0xA30` bit3~6 守備位置（0=P 1=C 2=1B 3=2B 4=3B 5=SS 6=LF 7=CF 8=RF）
    pub pos: u8,
    /// `+0x2C` bit4~6 捕手配球（0=G … 7=S）
    pub catcher: u8,
    /// 栄冠「野手風格／打擊積極性」等級（0=G … 6=A；沒有 S）。
    /// 畫面等級由 +0xA5B low3 決定；+0x10AE low3 是同步值。
    pub batting_aggression: u8,
    /// 栄冠「野手風格／選球眼」等級（0=G … 6=A；沒有 S）。
    /// 畫面等級由 +0xA53 bit3~5 決定；+0x10AA low3 是同步值。
    pub plate_discipline: u8,
    /// 栄冠「野手風格／人氣」。
    /// +0xA30 low3：實測 1=無、2=有；同 byte 的 bit3~6 是主要守備位置。
    pub popularity: bool,
    /// 栄冠的打擊姿勢/打球型態（0..6；見 [`BATTING_STYLE_NAMES`]）。
    /// 由 +0x2C bit7、+0x2D low2、+0xFB6 low3 三欄聯合判定；未知組合為 0xFF。
    pub batting_style: u8,
    /// `+0xA16` 隊伍 ID（明星選手模式用來分隊）
    pub team: u8,
    /// `+0xA50` 擅長・不擅長球路九宮格，畫面列優先，各 −3..+3
    pub zone: [i8; ZONE_N],
    pub speed: u16,
    pub stamina: u16,
    pub pack_hi: u16,
    /// Overall 計算使用的三個投手 packed 3-bit 欄位（P+28 DWORD bits22..30）。
    pub pitch_traits: [u8; 3],
    pub grade: u8,
    /// 栄冠球員信賴度（0..=200）
    pub trust: u8,
    /// 栄冠球員個性（0=非常普通 … 7=精明幹練）
    pub personality: u8,
    /// 栄冠球員情緒（0=超興奮, 1=興奮, 2=普通, 3=消沉）
    pub mood: u8,
    /// 栄冠球員體力（0..=500）
    pub energy: u16,
    /// 栄冠球員學力實際值（E=00..23, D=24..2D, C=2E..37, B=38..41, A=42..4B）
    pub academic: u8,
    /// 栄冠球員招募評價（0..=511；畫面以 1..5 星顯示）
    pub recruit_eval: u16,
    pub item: u8,
    pub book: u8,
    pub balls: Vec<Ball>,
    pub recs: Vec<OrigRec>,
    /// `+0x08..0x15` 的特殊能力 14 bytes ＝ 28 個 nibble
    pub abil: [u8; ABIL_BYTES],
}

/// 取出第 n 個 nibble（低 nibble 在前）
pub fn abil_nib(b: &[u8], n: usize) -> u8 {
    (b[n / 2] >> if n % 2 == 0 { 0 } else { 4 }) & 0xF
}

/// 只改寫單一 nibble（讀-改-寫，不動同一 byte 的另外半個）。
/// ⚠ 等級格的 4 ＝ signed −4，寫進去遊戲會當掉 —— 呼叫端要先擋掉。
pub fn write_abil_nibble(p: &Proc, obj: usize, n: usize, v: u8) -> bool {
    let off = obj + OFF_ABIL2 + n / 2;
    let cur = p.u8_at(off);
    let nv = if n % 2 == 0 { (cur & 0xF0) | (v & 0xF) } else { (cur & 0x0F) | (v << 4) };
    p.write(off, &[nv])
}

fn cstr(b: &[u8]) -> String {
    let e = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..e]).into_owned()
}

/// 一次要讀多少 bytes 才能解析出完整的 [`Player`]。
/// 最遠的欄位是 `+0x1512`（書籍使用量），取整到 `0x1520`。
pub const PLAYER_READ: usize = 0x1520;

/// 從已讀好的物件 bytes 取姓名（姓與名各自 NUL 結尾的 UTF-8）
pub fn name_from(b: &[u8]) -> String {
    let end = (OFF_NAME + 64).min(b.len());
    if OFF_NAME >= end {
        return String::new();
    }
    let parts: Vec<String> = b[OFF_NAME..end]
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .take(2)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    parts.join(" ")
}

pub fn read_name(p: &Proc, obj: usize) -> String {
    match p.read(obj + OFF_NAME, 64) {
        Some(b) => {
            let parts: Vec<String> = b
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .take(2)
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            parts.join(" ")
        }
        None => String::new(),
    }
}

/// 位址失效時會讀到亂碼 —— 明星選手模式在讀取存檔後物件位址會整批改變，
/// 每次寫入前都要用這個擋一下。
pub fn sane_name(nm: &str) -> bool {
    let s: String = nm.chars().filter(|c| !c.is_whitespace()).collect();
    if s.is_empty() || s.chars().count() > 12 || s.contains('\u{FFFD}') {
        return false;
    }
    s.chars().all(|c| {
        ('\u{3040}'..='\u{30FF}').contains(&c)
            || ('\u{4E00}'..='\u{9FFF}').contains(&c)
            || ('\u{FF66}'..='\u{FF9F}').contains(&c)
            || c.is_alphabetic()
    })
}

impl Player {
    /// **一次讀完整個物件再解析。**
    ///
    /// 舊版是逐欄位讀，每位選手要 ~24 次 `ReadProcessMemory`（光 12 筆原創球種記錄
    /// 就 12 次）。全掃 3000 位選手時那是 7 萬多次跨行程呼叫。
    pub fn load(p: &Proc, obj: usize) -> Option<Player> {
        Player::parse(&p.read(obj, PLAYER_READ)?, obj)
    }

    /// 從已經讀好的物件 bytes 解析。`b` 至少要有 [`PLAYER_READ`] 個 byte。
    pub fn parse(b: &[u8], obj: usize) -> Option<Player> {
        if b.len() < PLAYER_READ {
            return None;
        }
        let u8a = |o: usize| b[o];
        let u16a = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let pack = u16::from_le_bytes([b[OFF_PACK], b[OFF_PACK + 1]]);
        // 遊戲 Overall 計算器是從 P+28 起讀一個 DWORD：
        // bits 8..14=球速 raw、15..21=耐力、22..24/25..27/28..30=三個投手 3-bit 欄位。
        let pitcher_raw = u32::from_le_bytes([b[OFF_DEF], b[OFF_PACK], b[OFF_PACK + 1], b[OFF_PACK + 2]]);
        let mut pl = Player {
            addr: obj,
            name: name_from(b),
            defense: u8a(OFF_DEF),
            pos: ((u16::from_le_bytes([b[OFF_POS], b[OFF_POS + 1]]) >> POS_SHIFT) & 0xF) as u8,
            catcher: (u8a(OFF_CATCH) >> CATCH_SHIFT) & 7,
            batting_aggression: u8a(OFF_BATTING_AGGRESSION) & 7,
            plate_discipline: (u8a(OFF_PLATE_DISCIPLINE) >> PLATE_DISCIPLINE_SHIFT) & 7,
            popularity: (u8a(OFF_POPULARITY) & POPULARITY_MASK) == POPULARITY_ON,
            // 第三個參數是副本, 傳進去但不參與判斷（見 batting_style_from_raw）
            batting_style: batting_style_from_raw(u8a(OFF_CATCH), u8a(OFF_BATTING_STYLE), u8a(OFF_BATTING_SYNC))
                .unwrap_or(BATTING_STYLE_UNKNOWN),
            team: u8a(OFF_TEAM),
            speed: (pack & 0x7F) + 80,
            stamina: (pack >> 7) & 0x7F,
            pack_hi: pack & 0xC000,
            pitch_traits: [
                ((pitcher_raw >> 22) & 7) as u8,
                ((pitcher_raw >> 25) & 7) as u8,
                ((pitcher_raw >> 28) & 7) as u8,
            ],
            grade: u8a(OFF_GRADE),
            trust: u8a(OFF_TRUST),
            personality: u8a(OFF_PERSONALITY),
            mood: u8a(OFF_MOOD),
            energy: u16a(OFF_ENERGY),
            academic: u8a(OFF_ACADEMIC),
            recruit_eval: u16a(OFF_RECRUIT_EVAL),
            item: u8a(OFF_ITEM),
            book: u8a(OFF_BOOK),
            ..Default::default()
        };
        pl.stats.copy_from_slice(&b[OFF_STATS..OFF_STATS + 8]);
        pl.field.copy_from_slice(&b[0x18..0x20]);
        pl.abil.copy_from_slice(&b[OFF_ABIL2..OFF_ABIL2 + ABIL_BYTES]);
        let zraw = u32::from_le_bytes(b[OFF_ZONE..OFF_ZONE + 4].try_into().ok()?);
        for i in 0..ZONE_N {
            pl.zone[i] = zone_get(zraw, i);
        }
        for k in 0..N_BALL {
            let o = OFF_BALL + k * 3;
            let (id, pw, ct) = (b[o], b[o + 1], b[o + 2]);
            pl.balls.push(Ball { id, power: pw / 8, control: ct, move_: pw % 8 });
        }
        for i in 0..N_REC {
            let r = &b[OFF_ORIG + i * REC..OFF_ORIG + (i + 1) * REC];
            pl.recs.push(OrigRec {
                slot: u32::from_le_bytes([r[0], r[1], r[2], r[3]]),
                name: cstr(&r[REC_NAME..REC_NAME + REC_NAME_MAX]),
                base: r[REC_BASE],
                official: r[REC_OFFICIAL] == 1 || r[REC_KANA..REC_KANA + 8].iter().any(|&v| v != 0),
                raw: r.to_vec(),
            });
        }
        Some(pl)
    }

    /// 找出某個球種 slot 對應的原創球種記錄
    pub fn rec_for_slot(&self, slot: usize) -> Option<&OrigRec> {
        self.recs.iter().find(|r| r.slot == slot as u32)
    }

    /// 依目前已逆向出的遊戲公式，在修改器端直接計算總評（0..=999）。
    ///
    /// 這是不呼叫遊戲函式、不 hook / patch 的純本地計算。等同目前已確認的
    /// `calc_player_overall(..., modifier=null, param_3=0)` 路徑。
    ///
    /// 尚待更多實機樣本驗證的只有極少數特殊球種/模式修正；一般 roster 顯示可先用它對照。
    pub fn overall(&self) -> i32 {
        fn rating(v: i32) -> i32 {
            if v > 89 { ((v - 90) * 20) / 10 + 101 }
            else if v > 79 { ((v - 80) * 18) / 10 + 83 }
            else if v > 69 { ((v - 70) * 16) / 10 + 67 }
            else if v > 59 { ((v - 60) * 14) / 10 + 53 }
            else if v > 49 { ((v - 50) * 12) / 10 + 41 }
            else if v > 39 { ((v - 40) * 11) / 10 + 30 }
            else if v > 19 { v - 10 }
            else { v / 2 }
        }

        fn speed_rating(v: i32) -> i32 {
            if v > 169 { ((v - 170) * 24) / 5 + 151 }
            else if v > 164 { ((v - 165) * 22) / 5 + 129 }
            else if v > 159 { ((v - 160) * 20) / 5 + 109 }
            else if v > 154 { ((v - 155) * 18) / 5 + 91 }
            else if v > 149 { ((v - 150) * 16) / 5 + 75 }
            else if v > 144 { ((v - 145) * 15) / 5 + 60 }
            else if v > 139 { ((v - 140) * 14) / 5 + 46 }
            else if v > 134 { ((v - 135) * 13) / 5 + 33 }
            else if v > 129 { ((v - 130) * 12) / 5 + 21 }
            else if v > 124 { ((v - 125) * 11) / 5 + 10 }
            else { (v * 2 - 240).max(0) }
        }

        fn trait_rating(v: u8) -> i32 {
            match v {
                1 | 2 => 1,
                3..=6 => 2,
                7 => 4,
                _ => 0,
            }
        }

        fn signed_bits(v: u8, shift: u8, bits: u8) -> i32 {
            let mask = (1u16 << bits) - 1;
            let x = ((v as u16 >> shift) & mask) as i32;
            let sign = 1i32 << (bits - 1);
            if x & sign != 0 { x - (1i32 << bits) } else { x }
        }

        fn special_value(a: &[u8; ABIL_BYTES], id: usize) -> i32 {
            match id {
                0x00 => ((a[0x0d] >> 6) & 1) as i32,
                0x01 => signed_bits(a[0x0b], 4, 2),
                0x02 => signed_bits(a[0x05], 0, 3),
                0x03 => ((a[0] >> 3) & 1) as i32,
                0x04 => (a[0] >> 7) as i32,
                0x05 => ((a[5] >> 4) & 3) as i32,
                0x06 => ((a[1] >> 3) & 1) as i32,
                0x07 => signed_bits(a[0], 0, 3),
                0x08 => signed_bits(a[0], 4, 3),
                0x09 => (a[1] >> 7) as i32,
                0x0a => ((a[2] >> 3) & 1) as i32,
                0x0b => (a[2] >> 7) as i32,
                0x0c => ((a[3] >> 3) & 1) as i32,
                0x0d => signed_bits(a[5], 6, 2),
                0x0e => (a[3] >> 7) as i32,
                0x0f => (a[6] & 3) as i32,
                0x10 => ((a[4] >> 3) & 1) as i32,
                0x11 => (a[4] >> 7) as i32,
                0x12 => signed_bits(a[6], 2, 2),
                0x13 => ((a[5] >> 3) & 1) as i32,
                0x14 => ((a[0x0b] >> 6) & 1) as i32,
                0x15 => signed_bits(a[6], 4, 2),
                0x16 => (a[0x0b] >> 7) as i32,
                0x17 => (a[0x0c] & 1) as i32,
                0x18 => (a[6] >> 6) as i32,
                0x19 => signed_bits(a[7], 6, 2),
                0x1a => ((a[0x0c] >> 3) & 1) as i32,
                0x1b => signed_bits(a[8], 0, 2),
                0x1c => signed_bits(a[8], 2, 2),
                0x1d => ((a[0x0c] >> 4) & 1) as i32,
                0x1e => ((a[8] >> 4) & 3) as i32,
                0x1f => ((a[0x0c] >> 5) & 1) as i32,
                0x20 => (a[8] >> 6) as i32,
                0x21 => signed_bits(a[1], 0, 3),
                0x22 => signed_bits(a[9], 0, 2),
                0x23 => signed_bits(a[1], 4, 3),
                0x24 => signed_bits(a[9], 2, 2),
                0x25 => signed_bits(a[2], 0, 3),
                0x26 => signed_bits(a[2], 4, 3),
                0x27 => signed_bits(a[9], 4, 2),
                0x28 => signed_bits(a[9], 6, 2),
                0x29 => ((a[0x0c] >> 6) & 1) as i32,
                0x2a => signed_bits(a[10], 0, 2),
                0x2b => (a[0x0c] >> 7) as i32,
                0x2c => signed_bits(a[10], 2, 2),
                0x2d => signed_bits(a[10], 4, 2),
                0x2e => signed_bits(a[10], 6, 2),
                0x2f => signed_bits(a[0x0b], 0, 2),
                0x30 => (a[0x0d] & 1) as i32,
                0x31 => ((a[0x0d] >> 1) & 1) as i32,
                0x32 => signed_bits(a[3], 0, 3),
                0x33 => signed_bits(a[3], 4, 3),
                0x34 => ((a[0x0d] >> 2) & 1) as i32,
                0x35 => ((a[0x0d] >> 3) & 1) as i32,
                0x36 => signed_bits(a[0x0b], 2, 2),
                0x37 => signed_bits(a[4], 0, 3),
                0x38 => signed_bits(a[4], 4, 3),
                0x39 => ((a[0x0d] >> 4) & 1) as i32,
                0x3a => ((a[0x0d] >> 5) & 1) as i32,
                0x3b => signed_bits(a[7], 0, 2),
                0x3c => ((a[0x0c] >> 1) & 1) as i32,
                0x3d => signed_bits(a[7], 2, 2),
                0x3e => ((a[7] >> 4) & 3) as i32,
                0x3f => ((a[0x0c] >> 2) & 1) as i32,
                0x40 => (a[0x0d] >> 7) as i32,
                _ => 0,
            }
        }

        fn special_raw(id: usize, v: i32) -> i32 {
            if v == 0 { return 0; }
            match id {
                0x00 | 0x01 | 0x0e | 0x1b | 0x31 | 0x34 | 0x39 | 0x3a | 0x3c => 10,
                0x02 | 0x26 => v * 15,
                0x03 | 0x1a | 0x1d | 0x21 | 0x23 | 0x30 | 0x3f => 50,
                0x04 => 20,
                0x05 => match v { 1 => 25, 2 => 50, _ => 0 },
                0x06 | 0x40 => 60,
                0x07 | 0x18 | 0x28 | 0x2e | 0x32 | 0x33 | 0x36 | 0x37 | 0x3e => v * 25,
                0x08 | 0x25 | 0x38 | 0x3b => v * 30,
                0x09 | 0x0b | 0x0c | 0x0d | 0x10 | 0x11 | 0x17 | 0x1f | 0x29 | 0x35 => 25,
                0x0a | 0x13 | 0x14 | 0x16 | 0x2b => 15,
                0x0f | 0x1e => match v { 1 => 40, 2 => 100, _ => 0 },
                0x12 => match v { -1 => 40, 1 => 100, _ => 0 },
                0x15 | 0x22 => match v { -1 => -30, 1 => 25, _ => 0 },
                0x19 | 0x24 | 0x2a | 0x2c | 0x2d => -25,
                0x1c => v * 50,
                0x20 | 0x3d => v * 10,
                0x27 => match v { -1 => 20, 1 => 60, _ => 0 },
                0x2f => -40,
                _ => 0,
            }
        }

        fn special_quarter(id: usize, a: &[u8; ABIL_BYTES]) -> i32 {
            let raw = special_raw(id, special_value(a, id));
            if raw == 0 { 0 } else {
                let q = raw / 4; // Rust i32 跟 C 一樣向 0 截斷
                if q == 0 { if raw >= 0 { 1 } else { -1 } } else { q }
            }
        }

        fn pitch_power_rating(v: u8) -> i32 {
            match v & 7 {
                1 => 1, 2 => 3, 3 => 6, 4 => 15, 5 => 30, 6 => 60, 7 => 90, _ => 0,
            }
        }
        fn pitch_move_bonus(v: u8) -> i32 {
            match v & 7 {
                1 => 1, 2 => 3, 3 => 5, 4 => 12, 5 => 18, 6 => 25, 7 => 32, _ => 0,
            }
        }
        fn pitch_control_bonus(v: u8) -> i32 {
            match v & 7 {
                1 => 1, 2 => 2, 3 => 4, 4 => 6, 5 => 9, 6 => 12, 7 => 18, _ => 0,
            }
        }

        let stat = |i: usize| self.stats[i].min(99) as i32;
        let pos_rating = |p: usize| -> i32 {
            if p == 0 {
                if self.pos == 0 { self.defense as i32 } else { 0 }
            } else {
                self.field.get(p - 1).copied().unwrap_or(0) as i32
            }
        };

        // calc_player_overall 的共通部分：疲勞消除 40% + 特定共通特殊能力。
        let mut common = rating(stat(7)) * 40 / 100;
        for id in [0usize, 1, 2, 0x3d] {
            common += special_quarter(id, &self.abil);
        }

        // calc_fielder_component (FUN_145ABE560)
        let cr = rating(stat(0));
        let cl = rating(stat(1));
        let power = rating(stat(2));
        let speed = rating(stat(3));
        let arm = rating(stat(4));
        let throw_ = rating(stat(5));
        let catch = rating(stat(6));

        let mut field_sum = 0;
        for p in 1..=8usize {
            let mut x = rating(pos_rating(p));
            if p as u8 != self.pos { x /= 10; }
            field_sum += x;
        }

        let mut fielder = ((cl + cr) * 140) / 200
            + power * 160 / 100
            + speed * 50 / 100
            + field_sum * 50 / 100
            + throw_ * 40 / 100
            + catch * 40 / 100
            + arm * 40 / 100;

        let catcher_fit = pos_rating(1);
        if catcher_fit != 0 {
            let catcher_mul = (catcher_fit / 20).clamp(1, 4);
            let call_bonus = match self.catcher {
                1 => 1, 2 => 3, 3 => 5, 4 => 8, 5 => 12, 6 => 17, 7 => 23, _ => 0,
            };
            fielder += ((arm / 3) * catcher_fit) / 100 + call_bonus * catcher_mul;
        }

        // 原函式一般先 +3；只有 P+2C/P+2D 的位元組合 0x080（低仰角）不加。
        if self.batting_style != 1 {
            fielder += 3;
        }

        const FIELDER_SPECIALS: &[usize] = &[
            0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
            0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x34,0x35,0x36,0x37,0x38,0x39,
            0x3a,0x3c,0x3e,0x3f,0x40,
        ];
        for &id in FIELDER_SPECIALS {
            fielder += special_quarter(id, &self.abil);
        }

        if self.pos != 0 {
            return (common + fielder).clamp(0, 999);
        }

        // calc_pitcher_component (FUN_145ABE8E0)
        let mut pitcher_base = speed_rating(self.speed as i32);
        pitcher_base += self.pitch_traits.iter().copied().map(trait_rating).sum::<i32>();
        pitcher_base += rating(self.stamina as i32) * 50 / 100;
        pitcher_base += rating(pos_rating(0)) * 30 / 100;

        let mut pitch_scores = Vec::with_capacity(N_BALL);
        for (slot, b) in self.balls.iter().take(N_BALL).enumerate() {
            let id = b.id & 0x7f;
            if id == BALL_EMPTY { continue; }

            let mut score = pitch_power_rating(b.power);
            if slot == 5 || slot == 11 {
                score = score * 150 / 100;
            } else {
                // FUN_145AF5330(type)==5 就是不使用變化量；現有 ball_dir 的 5 即直球系。
                if ball_dir(id) != Some(5) {
                    score += pitch_move_bonus(b.move_);
                }
            }
            score += pitch_control_bonus(b.control);

            if matches!(id, 2 | 7 | 12 | 22 | 27 | 28 | 32 | 36 | 38 | 39) {
                score += 3;
            } else if matches!(id, 13 | 16 | 41 | 42 | 43) {
                score += 5;
            }
            pitch_scores.push(score);
        }
        pitch_scores.sort_unstable_by(|a, b| b.cmp(a));
        pitch_scores.truncate(10);

        let mut pitch_total = 0;
        for (i, &score) in pitch_scores.iter().enumerate() {
            if score == 0 { continue; }
            let weight = if i < 3 { 100 } else { (120 - (i as i32) * 10).max(10) };
            pitch_total += score * weight / 100;
        }
        if pitch_total > 300 {
            pitch_total = 300 + (pitch_total - 300) / 2;
        }

        let mut pitcher = pitcher_base + pitch_total - 4;
        const PITCHER_SPECIALS: &[usize] = &[
            0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,
            0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x3b,
        ];
        for &id in PITCHER_SPECIALS {
            pitcher += special_quarter(id, &self.abil);
        }

        // param_3=0 的二刀流加成路徑。
        let best_field = self.field.iter().copied().max().unwrap_or(0) as i32;
        let batting_sum = stat(0) + stat(1) + stat(2);
        if best_field >= 20 && batting_sum >= 150 {
            let w = (best_field + batting_sum) / 8;
            let hybrid = fielder * w / 100 + pitcher * (100 - w / 3) / 100;
            if hybrid > pitcher {
                return (common + hybrid).clamp(0, 999);
            }
        }

        let overall = common + pitcher + throw_ * 20 / 100 + catch * 20 / 100 + arm * 20 / 100;
        overall.clamp(0, 999)
    }

    pub fn ball_label(&self, slot: usize) -> String {
        let b = &self.balls[slot];
        if b.id == BALL_EMPTY {
            return "－（空）".into();
        }
        if b.id == BALL_ORIGINAL {
            return match self.rec_for_slot(slot) {
                Some(r) if !r.name.is_empty() => format!("原創：{}", zh_name(&r.name)),
                _ => "原創（沒有記錄→只會顯示「原創」）".into(),
            };
        }
        let mut s = ball_name(b.id);
        if ball_dir(b.id) != Some(slot % 6) {
            if let Some(d) = ball_dir(b.id) {
                s.push_str(&format!("  ⚠本屬方向{d}"));
            }
        }
        s
    }
}

// ─────────────────────────────────────────────── 寫入

pub fn write_stat(p: &Proc, obj: usize, idx: usize, v: u8) -> bool {
    p.write(obj + OFF_STATS + idx, &[v])
}

pub fn write_pack(p: &Proc, obj: usize, speed: u16, stam: u16, hi: u16) -> bool {
    let sp = speed.clamp(80, 207) - 80;
    let st = stam.min(127);
    let raw = (sp & 0x7F) | ((st & 0x7F) << 7) | hi;
    p.write(obj + OFF_PACK, &raw.to_le_bytes())
}

pub fn write_ball(p: &Proc, obj: usize, slot: usize, b: &Ball) -> bool {
    let bytes = if b.id == BALL_EMPTY {
        [BALL_EMPTY, 0, 0]
    } else {
        [b.id, b.power * 8 + b.move_, b.control]
    };
    p.write(obj + OFF_BALL + slot * 3, &bytes)
}

pub fn write_rec(p: &Proc, obj: usize, idx: usize, raw: &[u8], slot: usize) -> bool {
    let mut r = raw.to_vec();
    r.resize(REC, 0);
    r[..4].copy_from_slice(&(slot as u32).to_le_bytes());
    p.write(obj + OFF_ORIG + idx * REC, &r)
}

/// 決定某個球種 slot 該用第幾筆原創球種記錄。
/// **一定要現讀記憶體**，不要用畫面上的快照 —— 連續設定多個方向時，
/// 快照裡的記錄還是舊的，「找一筆空的」會一直回傳同一個索引，
/// 結果全部蓋在同一筆上，只有最後一顆生效（2026-07-26 踩過）。
pub fn find_rec_index(p: &Proc, obj: usize, slot: usize) -> Option<usize> {
    let mut free = None;
    for i in 0..N_REC {
        let s = p.u32_at(obj + OFF_ORIG + i * REC + REC_SLOT);
        if s == slot as u32 {
            return Some(i); // 已經指向這一格 → 換掉它
        }
        if s >= REC_UNUSED_SLOT && free.is_none() {
            free = Some(i);
        }
    }
    free
}

pub fn clear_rec(p: &Proc, obj: usize, idx: usize) -> bool {
    let mut r = vec![0u8; REC];
    r[..4].copy_from_slice(&REC_UNUSED_SLOT.to_le_bytes());
    r[REC_BASE] = BALL_EMPTY;
    p.write(obj + OFF_ORIG + idx * REC, &r)
}

// ─────────────────────────────────────────────── 栄冠（高中）指標鏈
// 2026-08-28 新版：同一個 static root 分成「部員名單」與「道具」兩條鏈
// （wrapper 鏈由 PR #1 找到；終點跟 `modeobj + 0x185440` 是同一個位置）。

/// 栄冠 singleton 的靜態位址。
/// 原作者路徑：`[exe + KOSHIEN_STATIC] -> +0x70 = ModeObj`。
pub const KOSHIEN_STATIC: usize = 0x139C5EA0;
pub const KOSHIEN_COUNT: usize = 0x185448;
pub const KOSHIEN_ARRAY: usize = 0x185450;

// ── 新生招募候選人表
// Region[n] = modeobj + 0x185F78 + n*0x60
// +0x08..+0x50 共 10 個 Candidate pointer；Candidate +0x18 = Player Object。
pub const RECRUIT_REGION_BASE: usize = 0x185F78;
pub const RECRUIT_REGION_STRIDE: usize = 0x60;
pub const RECRUIT_CANDIDATE_N: usize = 10;
pub const RECRUIT_PLAYER_FROM_CANDIDATE: usize = 0x18;
/// 目前 UI 先以 47 個都道府縣 index（0..46）提供選擇。
pub const RECRUIT_REGION_N: usize = 49;

/// 栄冠的 mode 物件（`[static] -> +0x70`），道具與練習效果都掛在它底下。
/// 離開該模式時 singleton 會變回 0（回傳 0 屬正常）。
pub fn koshien_modeobj(p: &Proc) -> usize {
    if p.base == 0 {
        return 0;
    }
    let l1 = p.u64_at(p.base + KOSHIEN_STATIC) as usize;
    if l1 == 0 {
        return 0;
    }
    p.u64_at(l1 + 0x70) as usize
}

// ─────────────────── 栄冠部員名單：vector 特徵掃描（2026-08-29 遊戲更新後改用）

/// 一個位址看起來像不像遊戲堆積上的物件。
fn plausible_heap(a: usize) -> bool {
    (0x1000_0000..0x2_0000_0000).contains(&a) && a % 8 == 0
}

/// 讀取指定地區的新生招募候選人。
/// 回傳 `(candidate_index, Candidate base, Player Object base)`。
///
/// Candidate 結構已實機確認：`Player Object = Candidate + 0x18`，
/// 因此姓名、主守備、野手/投手能力、特殊能力都直接沿用既有 `Player` parser。
pub fn recruit_candidates(p: &Proc, region: usize) -> Vec<(usize, usize, usize)> {
    if region >= RECRUIT_REGION_N || p.base == 0 {
        return Vec::new();
    }

    let read_from_modeobj = |m: usize| -> Vec<(usize, usize, usize)> {
        if m < 0x10000 {
            return Vec::new();
        }
        let region_base = m + RECRUIT_REGION_BASE + region * RECRUIT_REGION_STRIDE;
        let mut out = Vec::new();
        for i in 0..RECRUIT_CANDIDATE_N {
            let c = p.u64_at(region_base + (i + 1) * 8) as usize;
            if c < 0x10000 {
                continue;
            }
            let obj = c + RECRUIT_PLAYER_FROM_CANDIDATE;
            let name = read_name(p, obj);
            // 尚未生成的地區會有 Candidate slot，但姓名是遊戲預設的「未初期化」。
            // 這種不能算真正可招募候選人。
            if sane_name(&name) && name.trim() != "未初期化" {
                out.push((i, c, obj));
            }
        }
        out
    };

    // 新生招募與原作者榮冠 roster 共用同一個固定 ModeObj。
    // 是否允許讀 Region/Candidate 由 pedit 的 koshien_roster gate 負責。
    read_from_modeobj(koshien_modeobj(p))
}


/// 只列出目前真正有候選球員名單的地區。
/// 判定標準不是 pointer 非 0，而是至少一位 Candidate 能解析出合法姓名；
/// 因此遊戲尚未生成、姓名顯示「未初期化」的地區不會出現在 UI。
pub fn recruit_available_regions(p: &Proc) -> Vec<usize> {
    (0..RECRUIT_REGION_N)
        .filter(|&r| !recruit_candidates(p, r).is_empty())
        .collect()
}

// ── 新生候選人：天才 flag
// 已實機確認：FUN_1465B4FD0 控制 Player Object +0xE3C bit1。
// 新生生成時原生判定為 FUN_1465AB250(99) < 1，因此預設約 1%。
pub const OFF_TALENT_FLAGS: usize = 0xE3C;
pub const TALENT_FLAG_MASK: u32 = 0x0000_0002;

pub fn player_is_talent(p: &Proc, obj: usize) -> bool {
    p.u32_at(obj + OFF_TALENT_FLAGS) & TALENT_FLAG_MASK != 0
}

pub fn write_player_talent(p: &Proc, obj: usize, talent: bool) -> bool {
    let old = p.u32_at(obj + OFF_TALENT_FLAGS);
    let new = if talent { old | TALENT_FLAG_MASK } else { old & !TALENT_FLAG_MASK };
    p.write(obj + OFF_TALENT_FLAGS, &new.to_le_bytes())
}

// ── 新生天才出現機率 runtime patch
// Ghidra 0x145E2BF37 / exe+0x5E2BF37：83 F8 01 = cmp eax,1。
// EAX 是 0..99 的亂數，後面 `setl dl`，因此把 imm8 改成 0..100
// 就能直接得到 0%..100% 的天才出現機率。
pub const TALENT_RATE_PATCH_RVA: usize = 0x5E2BF37;
pub const TALENT_RATE_DEFAULT: u8 = 1;

pub fn talent_rate(p: &Proc) -> Option<u8> {
    let site = p.base + TALENT_RATE_PATCH_RVA;
    let cur = p.read(site, 3)?;
    if cur.len() == 3 && cur[0] == 0x83 && cur[1] == 0xF8 && cur[2] <= 100 {
        Some(cur[2])
    } else {
        None
    }
}

pub fn set_talent_rate(p: &Proc, rate: u8) -> Result<(), String> {
    if rate > 100 {
        return Err("天才出現機率必須介於 0～100".into());
    }
    let site = p.base + TALENT_RATE_PATCH_RVA;
    let cur = p.read(site, 3).ok_or("讀不到天才機率 patch 位址")?;
    if cur.len() != 3 || cur[0] != 0x83 || cur[1] != 0xF8 {
        return Err(format!("天才機率 patch 位址驗證失敗：exe+0x{:X} 不是預期的 cmp eax,imm8", TALENT_RATE_PATCH_RVA));
    }
    if cur[2] > 100 {
        return Err(format!("天才機率目前值異常：{}", cur[2]));
    }
    if !p.write_code(site + 2, &[rate]) {
        return Err("無法寫入天才出現機率".into());
    }
    Ok(())
}

// ── 新生招募成功率 100%：純資料表 patch
//
// 2026-09-13 重新逆向確認 FUN_1465C64A0 的實際公式：
//   chance = base[param_2] + max(item_effect, 0) + bonus
//   success = random(0..99) < chance
//
// base table  : Ghidra VA 0x14B18A3E8 → RVA 0x0B18A3E8
// bonus table : Ghidra VA 0x14B18A400 → RVA 0x0B18A400
//
// 原始 base  = [0, 50, 60, 70, 80, 90]
// 原始 bonus = [(0,+20), (100,+10), (140,0), (180,-10), (220,-20), (260,-30)]
//
// 100% 模式只改：
//   base[1..=5] → 100（base[0] 的特殊語意尚未確認，因此保持 0，不碰）
//   bonus 的 0/-10/-20/-30 → +10；原本 +20/+10 保持不變。
// 這樣有效 tier 的 chance 最低為 100 + max(param_3,0) + 10 >= 110。
// FUN_1465C64A0 的最高反應第一層門檻是 chance-10，因此最低也有 100，
// 對 random(0..99) 必定成立：同時保證招募成功與最高反應，不改 executable control flow。
pub const RECRUIT_RATE_BASE_TABLE_RVA: usize = 0x0B18_A3E8;
pub const RECRUIT_RATE_BONUS_TABLE_RVA: usize = 0x0B18_A400;

const RECRUIT_RATE_BASE_ORIG: [i32; 6] = [0, 50, 60, 70, 80, 90];
const RECRUIT_RATE_BONUS_ORIG: [i32; 12] = [
    0, 20,
    100, 10,
    140, 0,
    180, -10,
    220, -20,
    260, -30,
];

// (RVA, 原始值, 100% 模式值)。只列真正會被修改的 9 個 DWORD。
const RECRUIT_RATE_DATA_PATCH: [(usize, i32, i32); 9] = [
    (RECRUIT_RATE_BASE_TABLE_RVA + 0x04, 50, 100),
    (RECRUIT_RATE_BASE_TABLE_RVA + 0x08, 60, 100),
    (RECRUIT_RATE_BASE_TABLE_RVA + 0x0C, 70, 100),
    (RECRUIT_RATE_BASE_TABLE_RVA + 0x10, 80, 100),
    (RECRUIT_RATE_BASE_TABLE_RVA + 0x14, 90, 100),
    (RECRUIT_RATE_BONUS_TABLE_RVA + 0x14, 0, 10),
    (RECRUIT_RATE_BONUS_TABLE_RVA + 0x1C, -10, 10),
    (RECRUIT_RATE_BONUS_TABLE_RVA + 0x24, -20, 10),
    (RECRUIT_RATE_BONUS_TABLE_RVA + 0x2C, -30, 10),
];

// 只記錄「本次修改器 instance 實際成功套用」的 PID。
// 不會在啟動時掃描或擅自恢復其他工具留下的資料修改。
static RECRUIT_RATE_DATA_PATCH_PID: std::sync::Mutex<Option<u32>> =
    std::sync::Mutex::new(None);

fn read_i32_exact(p: &Proc, addr: usize) -> Option<i32> {
    let b = p.read(addr, 4)?;
    (b.len() == 4).then(|| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// 靜態表通常位於唯讀映射；短暫開寫入權限，寫完立即恢復原 protection。
/// 若該頁原本可執行，仍使用 PAGE_EXECUTE_READWRITE，避免短暫移除 execute 權限；
/// 一般 .rdata 則用 PAGE_READWRITE。這是資料寫入，不配置 executable memory，也不改 JMP。
fn write_static_i32(p: &Proc, addr: usize, value: i32) -> bool {
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READWRITE_LOCAL: u32 = 0x40;

    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let queried = unsafe {
        VirtualQueryEx(
            p.h,
            addr as *const c_void,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if queried == 0 {
        return false;
    }
    let executable_page = matches!(mbi.Protect & 0xFF, 0x10 | 0x20 | 0x40 | 0x80);
    let temporary = if executable_page {
        PAGE_EXECUTE_READWRITE_LOCAL
    } else {
        PAGE_READWRITE
    };

    let mut old = 0u32;
    unsafe {
        if VirtualProtectEx(p.h, addr as *mut c_void, 4, temporary, &mut old) == 0 {
            return false;
        }
    }

    let ok = p.write(addr, &value.to_le_bytes());
    let mut back = 0u32;
    unsafe {
        VirtualProtectEx(p.h, addr as *mut c_void, 4, old, &mut back);
    }
    ok
}

/// 啟用前驗證完整兩張 table，避免遊戲更新後 RVA / layout 已變卻仍盲寫。
fn verify_recruit_rate_original_tables(p: &Proc) -> Result<(), String> {
    for (i, &want) in RECRUIT_RATE_BASE_ORIG.iter().enumerate() {
        let addr = p.base + RECRUIT_RATE_BASE_TABLE_RVA + i * 4;
        let got = read_i32_exact(p, addr)
            .ok_or_else(|| format!("讀不到招募 base table index {i}"))?;
        if got != want {
            return Err(format!(
                "招募 base table 驗證失敗：index {i} 目前為 {got}，預期 {want}"
            ));
        }
    }

    for (i, &want) in RECRUIT_RATE_BONUS_ORIG.iter().enumerate() {
        let addr = p.base + RECRUIT_RATE_BONUS_TABLE_RVA + i * 4;
        let got = read_i32_exact(p, addr)
            .ok_or_else(|| format!("讀不到招募 bonus table index {i}"))?;
        if got != want {
            return Err(format!(
                "招募 bonus table 驗證失敗：index {i} 目前為 {got}，預期 {want}"
            ));
        }
    }
    Ok(())
}

fn verify_recruit_rate_patch_entries(p: &Proc, patched: bool) -> Result<(), String> {
    for &(rva, orig, patched_value) in &RECRUIT_RATE_DATA_PATCH {
        let want = if patched { patched_value } else { orig };
        let got = read_i32_exact(p, p.base + rva)
            .ok_or_else(|| format!("讀不到招募機率資料表 exe+0x{rva:X}"))?;
        if got != want {
            return Err(format!(
                "招募機率資料表狀態不符：exe+0x{rva:X} 目前為 {got}，預期 {want}"
            ));
        }
    }
    Ok(())
}

pub fn recruit_rate_100_enabled(p: &Proc) -> bool {
    let g = RECRUIT_RATE_DATA_PATCH_PID
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    matches!(*g, Some(pid) if pid == p.pid)
        && verify_recruit_rate_patch_entries(p, true).is_ok()
}

/// 還原本次修改器 instance 自己套用的「招募機率100%」資料表 patch。
///
/// 安全原則：
/// - 沒有本 instance 的 active PID 記錄 → 不動任何資料。
/// - 還原前必須確認 9 個欄位仍是本修改器寫入的值；若被其他工具改過，拒絕覆蓋。
/// - 若中途寫入失敗，嘗試把已還原的欄位重新套回 patched 值，避免半套狀態。
pub fn reset_recruit_rate_patch(p: &Proc) -> Result<bool, String> {
    let mut g = RECRUIT_RATE_DATA_PATCH_PID
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match *g {
        Some(pid) if pid == p.pid => {}
        _ => return Ok(false),
    }

    verify_recruit_rate_patch_entries(p, true)?;

    let mut restored = 0usize;
    for &(rva, orig, _) in &RECRUIT_RATE_DATA_PATCH {
        if !write_static_i32(p, p.base + rva, orig) {
            // best-effort rollback：把前面已還原的欄位重新設回 patched 值。
            for &(rrva, _, patched_value) in RECRUIT_RATE_DATA_PATCH[..restored].iter().rev() {
                let _ = write_static_i32(p, p.base + rrva, patched_value);
            }
            return Err(format!("還原招募機率資料表失敗：exe+0x{rva:X}"));
        }
        restored += 1;
    }

    verify_recruit_rate_patch_entries(p, false)?;
    *g = None;
    Ok(true)
}

pub fn set_recruit_rate_100(p: &Proc, enable: bool) -> Result<(), String> {
    if !enable {
        reset_recruit_rate_patch(p)?;
        return Ok(());
    }

    let mut g = RECRUIT_RATE_DATA_PATCH_PID
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    if let Some(pid) = *g {
        if pid == p.pid {
            // UI 重複要求 enable 時，不重寫；但仍確認資料沒有被外部改掉。
            verify_recruit_rate_patch_entries(p, true)?;
            return Ok(());
        }
        // 遊戲已換 PID；舊 process 的記憶體已不存在，丟掉舊 instance 記錄。
        *g = None;
    }

    // 啟用前驗證完整兩張原始 table，而不是只驗證要改的 8 格。
    verify_recruit_rate_original_tables(p)?;

    let mut written = 0usize;
    for &(rva, orig, patched_value) in &RECRUIT_RATE_DATA_PATCH {
        if !write_static_i32(p, p.base + rva, patched_value) {
            // best-effort rollback：前面已改的欄位全部恢復原始值。
            for &(rrva, rorig, _) in RECRUIT_RATE_DATA_PATCH[..written].iter().rev() {
                let _ = write_static_i32(p, p.base + rrva, rorig);
            }
            return Err(format!("寫入招募機率資料表失敗：exe+0x{rva:X}"));
        }
        let _ = orig; // 保留 tuple 語意，orig 在 rollback / restore 使用。
        written += 1;
    }

    if let Err(e) = verify_recruit_rate_patch_entries(p, true) {
        // 驗證失敗也回滾，避免留下部分或未知狀態。
        for &(rva, orig, _) in RECRUIT_RATE_DATA_PATCH.iter().rev() {
            let _ = write_static_i32(p, p.base + rva, orig);
        }
        return Err(e);
    }

    *g = Some(p.pid);
    Ok(())
}

// ─────────────────────────────────────────────── LEGACY / DISABLED
// 舊的 code-cave 方案保留作為研究與相容性備案，但目前完全不參與 UI / lifecycle。
// 如未來真的需要重新啟用，先移除 `#[cfg(any())]`，並重新審核該版本遊戲的指令與 xref。
// 舊方案：exe+0x65C6542 的 `mov edi,99` → JMP cave → mov esi,100 → mov edi,99 → jump back。
#[cfg(any())]
mod legacy_recruit_rate_code_cave {
    use super::*;

    pub const RECRUIT_RATE_PATCH_RVA: usize = 0x65C6542;
    const RECRUIT_RATE_ORIG: [u8; 5] = [0xBF, 0x63, 0x00, 0x00, 0x00];
    static RECRUIT_RATE_CAVE: std::sync::Mutex<Option<(u32, usize)>> =
        std::sync::Mutex::new(None);

    pub fn recruit_rate_100_enabled_legacy(p: &Proc) -> bool {
        let g = RECRUIT_RATE_CAVE.lock().unwrap_or_else(|e| e.into_inner());
        matches!(*g, Some((pid, _)) if pid == p.pid)
    }

    pub fn reset_recruit_rate_patch_legacy(p: &Proc) -> Result<bool, String> {
        let site = p.base + RECRUIT_RATE_PATCH_RVA;
        let mut g = RECRUIT_RATE_CAVE.lock().unwrap_or_else(|e| e.into_inner());
        let cave = match *g {
            Some((pid, cave)) if pid == p.pid => cave,
            _ => return Ok(false),
        };

        if !p.write_code(site, &RECRUIT_RATE_ORIG) {
            return Err("無法還原招募機率原始指令".into());
        }
        unsafe { VirtualFreeEx(p.h, cave as *mut c_void, 0, MEM_RELEASE); }
        *g = None;
        Ok(true)
    }

    pub fn set_recruit_rate_100_legacy(p: &Proc, enable: bool) -> Result<(), String> {
        let site = p.base + RECRUIT_RATE_PATCH_RVA;
        if !enable {
            reset_recruit_rate_patch_legacy(p)?;
            return Ok(());
        }

        let mut g = RECRUIT_RATE_CAVE.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(*g, Some((pid, _)) if pid == p.pid) {
            return Ok(());
        }
        *g = None;

        let cur = p.read(site, 5).ok_or("讀不到招募機率 patch 位址")?;
        if cur.as_slice() != RECRUIT_RATE_ORIG {
            return Err(format!(
                "招募機率 patch 位址驗證失敗：exe+0x{:X} 不是預期指令",
                RECRUIT_RATE_PATCH_RVA
            ));
        }

        let mut cave = 0usize;
        for delta in (0x0100_0000usize..=0x7000_0000).step_by(0x0100_0000) {
            for addr in [p.base.wrapping_add(delta), p.base.wrapping_sub(delta)] {
                let q = unsafe {
                    VirtualAllocEx(
                        p.h,
                        addr as *mut c_void,
                        0x1000,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    )
                } as usize;
                if q != 0 {
                    let d = q as i128 - (site + 5) as i128;
                    if d >= i32::MIN as i128 && d <= i32::MAX as i128 {
                        cave = q;
                        break;
                    }
                    unsafe { VirtualFreeEx(p.h, q as *mut c_void, 0, MEM_RELEASE); }
                }
            }
            if cave != 0 {
                break;
            }
        }
        if cave == 0 {
            return Err("無法在招募機率程式碼附近配置 code cave".into());
        }

        let mut code = vec![0xBE, 0x64, 0, 0, 0, 0xBF, 0x63, 0, 0, 0, 0xE9, 0, 0, 0, 0];
        let back = (site + 5) as i128 - (cave + code.len()) as i128;
        if back < i32::MIN as i128 || back > i32::MAX as i128 {
            unsafe { VirtualFreeEx(p.h, cave as *mut c_void, 0, MEM_RELEASE); }
            return Err("code cave 回跳距離超出 rel32".into());
        }
        code[11..15].copy_from_slice(&(back as i32).to_le_bytes());
        if !p.write(cave, &code) {
            unsafe { VirtualFreeEx(p.h, cave as *mut c_void, 0, MEM_RELEASE); }
            return Err("無法寫入招募機率 code cave".into());
        }

        let rel = cave as i128 - (site + 5) as i128;
        let mut jmp = [0xE9, 0, 0, 0, 0];
        jmp[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
        if !p.write_code(site, &jmp) {
            unsafe { VirtualFreeEx(p.h, cave as *mut c_void, 0, MEM_RELEASE); }
            return Err("無法啟用招募機率 patch".into());
        }
        *g = Some((p.pid, cave));
        Ok(())
    }
}

/// 栄冠模式的部員名單。離開該模式時回傳空 Vec 屬正常。
///
/// 只走固定 `ModeObj + KOSHIEN_ARRAY` 路徑。
/// ModeObj 無效時立即回傳空名單，不做 wrapper 或全記憶體 fallback 掃描。
pub fn koshien_roster(p: &Proc) -> Vec<usize> {
    // 快速模式判斷：只接受固定 ModeObj 路徑。
    // ModeObj 無效時立即回傳空名單，絕不因為 reload/啟動/Region 刷新而觸發全記憶體掃描。
    let modeobj = koshien_modeobj(p);
    if modeobj == 0 {
        return Vec::new();
    }
    let n = p.u32_at(modeobj + KOSHIEN_COUNT) as usize;
    if n == 0 || n > 512 {
        return Vec::new();
    }
    (0..n)
        .map(|i| p.u64_at(modeobj + KOSHIEN_ARRAY + i * 8) as usize)
        .filter(|&o| o != 0)
        .collect()
}

/// 取得「可安全進行全隊修改」的榮冠 roster。
///
/// 與 `koshien_roster()` 不同，這裡採保守策略：
/// - wrapper / count 必須有效，count 需在合理範圍內；
/// - count 個 slot 必須全部是非 0、互不重複的 Player Object；
/// - 每個 Player Object 都必須能讀到合理姓名。
///
/// 任一檢查失敗就整批拒絕，避免 roster chain 尚未切到正確 state 時誤寫其他物件。
pub fn validated_koshien_roster(p: &Proc) -> Result<Vec<usize>, String> {
    // `koshien_roster()` 只走固定 ModeObj 快速路徑；不在榮冠時立即拒絕。
    let list = koshien_roster(p);
    if list.is_empty() {
        return Err("榮冠球員名單尚未就緒（目前不在榮冠模式，或固定 ModeObj 尚未有效）".into());
    }
    if list.len() > 128 {
        return Err(format!("榮冠球員人數異常：{}", list.len()));
    }

    let mut seen = std::collections::HashSet::with_capacity(list.len());
    for (i, &obj) in list.iter().enumerate() {
        if obj == 0 {
            return Err(format!("榮冠 roster #{i} 的 Player Object 為 0"));
        }
        if !seen.insert(obj) {
            return Err(format!("榮冠 roster #{i} 出現重複 Player Object {obj:#x}"));
        }
        let name = read_name(p, obj);
        if !sane_name(&name) {
            return Err(format!("榮冠 roster #{i} 的 Player Object 驗證失敗 ({obj:#x})"));
        }
    }

    Ok(list)
}

// ─────────────────────────────────────────────── 常規作弊（道具類）

/// modeobj + 這個 ＝ 栄冠道具物件的指標；物件 `+0x0C` 才是資料起點
pub const KOSHIEN_ITEMOBJ: usize = 0x185438;
/// 栄冠道具是 i32 連續陣列，index ＝ 道具 ID，未持有 ＝ 0（UI 只顯示非零的格子）
pub const KOSHIEN_ITEM_N: usize = 221;
/// 跨模式共用道具表（i32 ×49）的候選位址，**新的在前**。
///
/// ⚠ 舊註解寫「資料位址跨版本沒變」—— 2026-08-29 的更新推翻了它，
/// 這張表也搬家了。而且**位移量跟 singleton 不一樣**
/// （`0x39FA60` vs `0x39F988`，差 0xD8），所以不能靠「整段平移」推算，
/// 一定要實際驗過。
pub const SHARED_ITEMS_CANDS: [usize; 2] = [0x19AECCE0, 0x1974D280];
/// 相容用：等於候選清單的第一個。
pub const SHARED_ITEMS: usize = SHARED_ITEMS_CANDS[0];
pub const SHARED_ITEM_N: usize = 49;

/// 挑出目前有效的共用道具表位址。
///
/// 道具數量的合理值域是 0..=999，而失效的舊位址讀出來混著 `0xFFFFFFFF`
/// 與 ASCII 字串 —— 用值域就能把它擋掉，不會誤寫到別的資料上。
pub fn shared_items_addr(p: &Proc) -> Option<usize> {
    if p.base == 0 {
        return None;
    }
    for off in SHARED_ITEMS_CANDS {
        let a = p.base + off;
        let Some(b) = p.read(a, SHARED_ITEM_N * 4) else { continue };
        let vals: Vec<u32> = (0..SHARED_ITEM_N)
            .map(|i| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap()))
            .collect();
        if vals.iter().all(|&v| v <= 999) && vals.iter().any(|&v| v > 0) {
            return Some(a);
        }
    }
    None
}
/// 明星選手「道具使用次數」byte 陣列的靜態指標候選，**新的在前**。
///
/// 2026-08-29 用 `pscan xref` 從計數函式往回追到的：
/// `exe+5BFBE39: mov rcx,[rip+0x13da02f8]` → `exe+1999C138`。
/// 舊的兩個是更新前的記錄（當時實測就是 0，位移 `0x39F9A0` 也跟這次其他位址對得上）。
///
/// ⚠ **這是純唯讀逆向得到的** —— 同樣的問題 2026-08-01 是靠 `pscan watch` 攔 RDI，
/// 但那次的結論是「陣列基址是呼叫端傳進來的參數、沒有靜態指標」，**是錯的**：
/// 18 個呼叫端裡確實有人傳參數，但也有人是從這個靜態指標讀。
/// 攔到的那一個呼叫端不能代表全部 —— `xref` 看得到全景，斷點只看得到當下那一次。
pub const STAR_USE_PTR_CANDS: [usize; 3] = [0x1999C138, 0x195FC798, 0x195FFA98];
/// 相容用：等於候選清單的第一個。
pub const STAR_USE_PTR: usize = STAR_USE_PTR_CANDS[0];
/// 陣列長度。程式碼裡的 `cmp ebx,0x110` 就是這個上限。
pub const STAR_USE_N: usize = 0x110;
/// 使用次數陣列裡道具佔的區間（index ＝ 道具 ID）
pub const STAR_USE_RANGE: std::ops::RangeInclusive<usize> = 3..=9;

/// 目前有效的「道具使用次數」陣列位址。未進入明星選手模式時回 None 屬正常。
pub fn star_use_array(p: &Proc) -> Option<usize> {
    if p.base == 0 {
        return None;
    }
    for off in STAR_USE_PTR_CANDS {
        let a = p.u64_at(p.base + off) as usize;
        if plausible_heap(a) && p.read(a, STAR_USE_N).is_some() {
            return Some(a);
        }
    }
    None
}

/// 「練習效果提升中」的剩餘天數，i16，**就在道具物件裡**（緊接 221 格道具陣列之後：
/// `+0x0C + 221*4 = +0x380`，再 2 bytes 就是它）。
/// 2026-07-27 以「寫 55／77 兩份副本比對畫面」確認過因果（另一份 `0xdd0cc4f2` 是副本，寫了畫面不動）。
pub const KOSHIEN_PRACBUFF: usize = 0x382;
/// 顯示端夾在 99，但**內部存得下 i16**：實測寫 9999 之後推進 7 天變 9992（照常每天 −1），
/// 遊戲不會把它改寫回來。9999 遊戲天 ≈ 27 年，一場栄冠才 3 年 —— **所以按一次就夠，不必定時重寫**。
pub const KOSHIEN_PRACBUFF_DAYS: i16 = 9999;

/// 栄冠道具物件本體。不在栄冠模式時回傳 None。
pub fn koshien_item_obj(p: &Proc) -> Option<usize> {
    let modeobj = koshien_modeobj(p);
    if modeobj == 0 {
        return None;
    }
    let obj = p.u64_at(modeobj + KOSHIEN_ITEMOBJ) as usize;
    (obj != 0).then_some(obj)
}

/// 栄冠道具陣列的資料起點。不在栄冠模式時回傳 None。
pub fn koshien_item_array(p: &Proc) -> Option<usize> {
    koshien_item_obj(p).map(|o| o + 0x0C)
}

/// 把「練習效果提升中」的剩餘天數設成 days（持續呼叫即等同永久）
pub fn set_koshien_pracbuff(p: &Proc, days: i16) -> bool {
    match koshien_item_obj(p) {
        Some(o) => p.write(o + KOSHIEN_PRACBUFF, &days.to_le_bytes()),
        None => false,
    }
}

/// 栄冠 221 格道具全部設成 val
pub fn set_koshien_items(p: &Proc, val: u32) -> bool {
    match koshien_item_array(p) {
        Some(a) => {
            let buf: Vec<u8> = (0..KOSHIEN_ITEM_N).flat_map(|_| val.to_le_bytes()).collect();
            p.write(a, &buf)
        }
        None => false,
    }
}

/// 跨模式共用道具 49 格全部設成 val（含栄冠 UI 最後 11 格與明星選手的 7 種）
pub fn set_shared_items(p: &Proc, val: u32) -> bool {
    if p.base == 0 {
        return false;
    }
    let Some(a) = shared_items_addr(p) else { return false };
    let buf: Vec<u8> = (0..SHARED_ITEM_N).flat_map(|_| val.to_le_bytes()).collect();
    p.write(a, &buf)
}

/// 栄冠「每人只能用 1 個道具／書籍最多 5 本」＝ `+0x1511`/`+0x1512` 兩個 byte。
/// 持續歸零就等同無限使用（上限判斷讀的就是它們）。回傳處理了幾位部員。
pub fn clear_koshien_use_limits(p: &Proc) -> usize {
    let Ok(roster) = validated_koshien_roster(p) else {
        return 0;
    };
    roster
        .iter()
        .filter(|&&o| p.write(o + OFF_ITEM, &[0, 0]))
        .count()
}

/// 榮冠：把目前 roster 中所有部員的情緒設為指定值。
/// 情緒欄位為 Player Object +0xE82；0=超興奮、1=興奮、2=普通、3=消沉。
/// 回傳成功寫入的部員人數。
pub fn set_koshien_all_mood(p: &Proc, mood: u8) -> usize {
    if mood > 3 {
        return 0;
    }
    let Ok(roster) = validated_koshien_roster(p) else {
        return 0;
    };
    roster
        .iter()
        .filter(|&&o| p.write(o + OFF_MOOD, &[mood]))
        .count()
}

/// 明星選手的道具使用次數歸零（＝解除「每種道具只能用 N 次」）。
/// ⚠ 沒進入該模式時靜態指標是 0，回傳 false 屬正常。
pub fn clear_star_item_uses(p: &Proc) -> bool {
    if p.base == 0 {
        return false;
    }
    let Some(arr) = star_use_array(p) else { return false };
    let n = STAR_USE_RANGE.end() - STAR_USE_RANGE.start() + 1;
    // ⚠ 只清道具那 7 格。整個陣列有 272 格，其餘是別的東西的計數
    //   （`pscan xref` 查出這個計數函式有 18 個呼叫端），清掉會波及無關的功能 ——
    //   這正是「不要 nop 掉 inc al」的同一個理由。
    p.write(arr + STAR_USE_RANGE.start(), &vec![0u8; n])
}

// ─────────────────────────────────────────────── 明星選手：成長經驗值（★ 能力值的真正來源）

/// ★★ 明星選手模式**不能直接改能力值** —— 那是衍生值。
///
/// 遊戲存的是各項的**累積經驗值**，能力值由 `exe+62A7A30` 算出來。
/// 每次結算（打完比賽／推進日期）都會重算並用 `memmove` 整份覆蓋選手物件，
/// 還會把差值報成「力量已下降 23 了！」。2026-07-31 由使用者 CE F5 攔到
/// `exe+62A6F6A: mov [r14+0x1a],al`（r14 ＝ 物件+8）反查 RSI 得到結構，再反組譯確認：
///
/// ```text
/// for i in 0..8 { if 經驗值 >= 門檻[i] { break } else { 等級++ } }
/// 能力值 = min(基礎值(等級) + (經驗值 − 門檻[等級]) / 分母(等級), 0x63)   // ← 硬上限 99
/// ```
///
/// 所以正解是**灌高經驗值**：走遊戲自己的成長管線，結算會算出 99 而不是把它改回去，
/// 報告畫面顯示的也是「上升」。實測 10 格全灌後
/// 球速 159→175km/h、耐力 75→99、其餘 7 項與投手守備適性全部 99。
pub const GROWTH_THRESH_OFF: usize = 0x118;
/// 門檻表：8 個 i32、遞減、全域固定。
/// 32 bytes 的固定樣式 ＝ 最可靠的定位特徵（AOB 命中 −0x118 ＝ 結構基址）。
pub const GROWTH_THRESHOLDS: [i32; 8] = [51000, 30000, 16000, 8000, 4000, 2000, 400, 0];
/// 結構內還有第二份同樣的門檻表，拿來排除「把第二份誤當第一份」的假命中。
pub const GROWTH_THRESH_OFF2: usize = 0x138;

/// 各等級的基礎能力值。`exe+5A9B150` 讀 `exe+0x841DBF0 + 等級*4`（呼叫時 edx=0）。
pub const GROWTH_BASE: [i32; 8] = [90, 80, 70, 60, 50, 40, 20, 0];
/// 各等級「每點能力值要幾點經驗值」。`exe+68EC740` 是兩層查表：
/// `值表[索引表[等級]]`，索引表 `exe+0xadf2ab0` ＝ `7,6,5,4,3,2,1,0`，
/// 值表 `exe+0xadf2a50` ＝ `20,80,200,400,800,1400,2100,2400,…`
pub const GROWTH_DENOM: [i32; 8] = [2400, 2100, 1400, 800, 400, 200, 80, 20];

/// 經驗值 → 能力值（`exe+62A7A30` 的等價實作）。
///
/// 驗算：`19069` → 等級2 → `70 + (19069−16000)/1400 = 72`（實際力量就是 72）。
pub fn stat_for_exp(exp: i32) -> i32 {
    let l = GROWTH_THRESHOLDS.iter().position(|&t| exp >= t).unwrap_or(7);
    (GROWTH_BASE[l] + (exp - GROWTH_THRESHOLDS[l]) / GROWTH_DENOM[l]).clamp(0, 99)
}

/// 能力值 → 需要的經驗值（上面那條的反解）。
///
/// 取第一個 `基礎值[L] <= 目標` 的等級 L，`exp = 門檻[L] + (目標 − 基礎[L]) * 分母[L]`。
/// 驗算：`99` → `51000 + 9*2400 = 72600` ＝ 遊戲自己的經驗值上限，完全對上。
pub fn exp_for_stat(v: i32) -> i32 {
    let v = v.clamp(0, 99);
    let l = GROWTH_BASE.iter().position(|&b| v >= b).unwrap_or(7);
    GROWTH_THRESHOLDS[l] + (v - GROWTH_BASE[l]) * GROWTH_DENOM[l]
}
/// 經驗值陣列（i32）的位移與格數。
/// 已由反組譯逐一對到欄位：
/// `+0x40`對右 `+0x44`對左 `+0x48`力量 `+0x4C`速度 `+0x50`接球 `+0x54`傳球
/// `+0x58`臂力 `+0x5C`球速/耐力 `+0x60`投手適性 `+0x64`守備適性陣列
pub const GROWTH_EXP_OFF: usize = 0x40;
pub const GROWTH_EXP_N: usize = 10;
/// 10 格的欄位名（由 setter 的寫入位移反查得出，見上表）
pub const GROWTH_EXP_NAMES: [&str; GROWTH_EXP_N] = [
    "對右打擊", "對左打擊", "力量", "速度", "接球",
    "傳球", "臂力", "球速", "耐力", "投手適性",
];
/// ⚠ **不能用 `+0x17C` 的 72600**：`+0x5C` 原值就有 79832，寫 72600 等於**調低**，
/// 實測球速因此完全不動（害我誤判成「球速不受經驗值管理」）。
/// 要用 `+0x18C` 那一組的上限 223600。
pub const GROWTH_EXP_MAX: i32 = 223600;
/// live 選手物件 → 它的經驗值結構的固定位移（跨遊戲重開實測仍成立）。
/// 有這個就不必每次都全記憶體掃描。
pub const GROWTH_FROM_PLAYER: usize = 0xB014;

/// 這個位址是不是一個成長經驗值結構 —— 兩份門檻表都要對上。
///
/// ⚠ 只驗第一份會漏掉一半：兩份門檻表相距 `0x20`，
/// 拿第二份的命中去減 `0x118` 會得到「基址+0x20」這種假基址。
pub fn growth_struct_ok(p: &Proc, base: usize) -> bool {
    let want: Vec<u8> = GROWTH_THRESHOLDS.iter().flat_map(|v| v.to_le_bytes()).collect();
    for off in [GROWTH_THRESH_OFF, GROWTH_THRESH_OFF2] {
        match p.read(base + off, want.len()) {
            Some(b) if b == want => {}
            _ => return false,
        }
    }
    true
}

/// 從 live 選手物件推出它的經驗值結構（免掃描，0.1 秒）。
pub fn growth_struct_for(p: &Proc, player: usize) -> Option<usize> {
    let base = player.checked_add(GROWTH_FROM_PLAYER)?;
    growth_struct_ok(p, base).then_some(base)
}

/// 讀出 10 格經驗值
pub fn growth_exp(p: &Proc, base: usize) -> Vec<i32> {
    (0..GROWTH_EXP_N)
        .map(|i| p.u32_at(base + GROWTH_EXP_OFF + i * 4) as i32)
        .collect()
}

/// 把 10 格能力經驗值全部灌到上限。下次結算時遊戲自己會算出 99。
pub fn set_growth_exp(p: &Proc, base: usize, val: i32) -> bool {
    if !growth_struct_ok(p, base) {
        return false; // 位址失效就拒寫 —— 明星選手模式讀檔後物件會整批搬家
    }
    (0..GROWTH_EXP_N).all(|i| p.write(base + GROWTH_EXP_OFF + i * 4, &val.to_le_bytes()))
}

/// 經驗值灌滿後，結算會算出來的結果值（實測）。
/// 直接寫進選手物件 ＝ **不用等練習就立即生效**；就算不精確也無妨 ——
/// 經驗值已經滿了，下次結算會把它校正成正確值。
pub const GROWTH_RESULT_STAT: u8 = 99;
pub const GROWTH_RESULT_SPEED: u16 = 175;
pub const GROWTH_RESULT_STAMINA: u16 = 99;

/// 把「經驗值滿了之後會得到的結果」直接寫進選手物件。
///
/// 球種當初之所以「連練習都不用」就生效，是因為同時做了兩件事：
/// **直接寫顯示值**（立即看到）＋**灌經驗值**（結算後也維持）。
/// 能力值這邊只灌經驗值的話，就得等結算重算 —— 所以補上這一半。
pub fn apply_growth_result(p: &Proc, player: usize) -> bool {
    if !sane_name(&read_name(p, player)) {
        return false; // 位址失效就拒寫
    }
    let hi = p.u16_at(player + OFF_PACK) & 0xC000; // bit14-15 是別的旗標，要保留
    let ok1 = p.write(player + OFF_STATS, &[GROWTH_RESULT_STAT; 8]);
    let ok2 = write_pack(p, player, GROWTH_RESULT_SPEED, GROWTH_RESULT_STAMINA, hi);
    let ok3 = p.write(player + OFF_DEF, &[GROWTH_RESULT_STAT]);
    // +0x18..0x1F 的野手守備適性：沒有經驗值進度條的守位不受結算管理，直接寫就成立
    let ok4 = p.write(player + 0x18, &[GROWTH_RESULT_STAT; 8]);
    ok1 && ok2 && ok3 && ok4
}

/// **8 個野手守位**的經驗值：`+0x68 + index*4`，順序 ＝ 捕/一/二/三/遊/左/中/右，
/// 跟選手物件 `+0x18+index` 的守備適性陣列一一對應。投手的在 `+0x60`/`+0x64`（屬能力區）。
///
/// 2026-08-01 驗證：使用者練了二壘手之後，只有 `+0x70`（index 2）從 0 變成 300，
/// 而畫面上正好只有二壘手掉回 G 15 —— 其餘守位維持直接寫入的 99。
pub const GROWTH_FIELD_OFF: usize = 0x68;
pub const GROWTH_FIELD_N: usize = 8;
/// ⚠ 守位用 **72600**（＝投手 `+0x60` 實測算出 99 的值），不是球種的 51000。
/// 守備適性顯示 0~99，跟能力值同型；51000 只到門檻最高階，未必算得出 99。
pub const GROWTH_FIELD_MAX: i32 = 72600;

/// 把 8 個野手守位的經驗值灌滿 ＝ 練任何守位都不會再被算回 G。
pub fn set_field_exp(p: &Proc, base: usize) -> bool {
    if !growth_struct_ok(p, base) {
        return false;
    }
    (0..GROWTH_FIELD_N).all(|i| {
        p.write(base + GROWTH_FIELD_OFF + i * 4, &GROWTH_FIELD_MAX.to_le_bytes())
    })
}

/// 球種數值的經驗值區。**從 `0x88` 起** —— `0x68`..`0x84` 是守位，
/// 兩者上限不同（51000 vs 72600），不可混在一起處理。
pub const GROWTH_EXTRA_LO: usize = 0x88;
pub const GROWTH_EXTRA_HI: usize = 0x114;
/// ⚠ **這一區只能灌到 51000，不能用 `GROWTH_EXP_MAX`(223600)。**
///
/// 球種顯示的是 **G~S 共 8 級**，不是能力值的 0~99 —— 值域完全不同。
/// 真實資料裡已滿級的球種經驗值就是 `51000`（＝門檻表的最高一階），
/// 那就是遊戲自己會產生的最大值。2026-08-01 寫 223600 進去，
/// 能力值頁面正常、**一開「球種」頁就崩潰**。
///
/// 通則：**寫入值不得超過該欄位在真實資料中觀察到的最大值**。
pub const GROWTH_EXTRA_MAX: i32 = 51000;

/// 提升「已存在項目」的經驗值 —— **只動本來非零的格，回傳提升了幾格**。
///
/// ⚠⚠ **絕對不要把值為 `0` 的格一起灌**（2026-08-01 這樣做讓使用者的遊戲當掉）。
/// 這一區是稀疏的：`0` ＝ **該項目不存在**（沒學會的球種、不能守的守位），
/// 不是「還沒練」。給不存在的項目經驗值，遊戲就會去顯示一個不存在的條目而崩潰 ——
/// 跟特殊能力那三次崩潰（憑空生出沒觀察過的能力）是完全同一型的錯。
///
/// 非零才代表項目真的存在：實測新增一顆滑球後，`+0xD0/D4/D8` 就從 0 變成
/// `100/100/400`（對應畫面的球威G／控球G／變化幅度F），中外野練過之後 `+0x80` 從 200 變 500。
/// 球種 slot 的經驗值位置：`結構 + 0x88 + slot*12`，三格 ＝ 球威／控球／變化幅度。
/// 12/12 驗證過：有球的 slot 三格非零、空 slot 全 0、
/// **直球系（方向5）第三格必為 0**（火の玉與真二縫線都是 `51000/51000/0`）。
pub const GROWTH_BALL_OFF: usize = 0x88;
pub const GROWTH_BALL_STRIDE: usize = 12;

/// 把某個球種 slot 的經驗值灌滿 ＝ 該球三項直接 S。
///
/// ⚠ **呼叫前那個 slot 必須真的有球**（先寫球種 ID，再寫這裡）。
/// 對空 slot 寫經驗值 ＝ 憑空創造不存在的項目，遊戲會當掉。
/// 直球系不寫第三格，維持 0。
pub fn set_ball_exp(p: &Proc, base: usize, slot: usize) -> bool {
    if slot >= N_BALL || !growth_struct_ok(p, base) {
        return false;
    }
    let off = base + GROWTH_BALL_OFF + slot * GROWTH_BALL_STRIDE;
    let n = if slot % 6 == 5 { 2 } else { 3 }; // 方向5 ＝ 直球系, 沒有變化幅度
    (0..n).all(|k| p.write(off + k * 4, &GROWTH_EXTRA_MAX.to_le_bytes()))
}

pub fn raise_growth_extra(p: &Proc, base: usize) -> usize {
    if !growth_struct_ok(p, base) {
        return 0;
    }
    let val = GROWTH_EXTRA_MAX;
    let mut n = 0;
    let mut off = GROWTH_EXTRA_LO;
    while off <= GROWTH_EXTRA_HI {
        let cur = p.u32_at(base + off) as i32;
        // cur > 0     ＝ 該項目存在（0 是「不存在」，寫了會當機）
        // cur < val   ＝ 還沒滿級；本來就 51000 的不要動，也絕不寫超過 51000
        if cur > 0 && cur < val && p.write(base + off, &val.to_le_bytes()) {
            n += 1;
        }
        off += 4;
    }
    n
}

/// 8 項能力（`+0x20` 陣列順序）→ 經驗值陣列 index。
/// ⚠ 兩邊順序**不一樣**：`+0x20` 是 對右/對左/力量/速度/**臂力/傳球/接球**/疲勞，
/// 經驗值是 對右/對左/力量/速度/**接球/傳球/臂力**/…（由各 setter 的寫入位移反查）。
/// 疲勞消除不受成長管理 → `-1`。
pub const STAT_TO_EXP: [i8; 8] = [0, 1, 2, 3, 6, 5, 4, -1];
/// 投手守備適性（`+0x28`）對應的經驗值 index。
/// ⚠ 2026-08-01 修正：先前誤記為 8。用實測值驗算才發現
/// `+0x60`=25000→耐力76、`+0x64`=6162→投手適性55，兩格是**顛倒**的。
pub const EXP_IDX_PITCHER_DEF: usize = 9;
/// 球速（packed 的 bit8-14）。**走另一套換算**，沒有反解公式。
pub const EXP_IDX_SPEED: usize = 7;
/// 耐力（packed 的 bit15-21）。跟能力值同一組換算表，**可以反解**。
pub const EXP_IDX_STAMINA: usize = 8;

/// 球速走**完全獨立**的一套換算（`exe+62A6B4C` 內嵌，不是 `62A7A30`）：
/// 基礎值表用第 **20** 組（`edx=0x14`）、門檻表在**結構 `+0x158`**、
/// 分母的值表是 `exe+0xadf2a90`（能力值是 `0xadf2a50`）。
///
/// 驗算：`80210` → 等級0 → `158 + 9610/9000 = 159`（實際球速 159）；
/// 反解 `175` → `70600 + 17*9000 = 223600` ＝ 一直在用的那個數，完全對上。
pub const SPEED_THRESH_OFF: usize = 0x158;
pub const SPEED_BASE: [i32; 8] = [158, 155, 152, 148, 144, 139, 134, 0];
pub const SPEED_DENOM: [i32; 8] = [9000, 7000, 4500, 2000, 1000, 500, 300, 150];
/// 球速下限 80（`mov eax,0x50`），上限 175（`mov ecx,0xAF`）。
/// ⚠ **上限有兩處**：`exe+62A6B87`（換算後夾）與 `exe+594A4C0`（setter 內再夾一次），
/// 只 patch 一處不會生效 —— 我第一次就漏了前者。
pub const SPEED_MIN: i32 = 80;

/// 目標球速 → 需要的經驗值。門檻表存在結構裡，所以要傳 base。
pub fn exp_for_speed(p: &Proc, base: usize, v: i32) -> i32 {
    let th: Vec<i32> = (0..8)
        .map(|i| p.u32_at(base + SPEED_THRESH_OFF + i * 4) as i32)
        .collect();
    let v = v.max(SPEED_MIN);
    let l = SPEED_BASE.iter().position(|&b| v >= b).unwrap_or(7);
    th[l] + (v - SPEED_BASE[l]) * SPEED_DENOM[l]
}

/// 經驗值 → 球速（驗算用）
pub fn speed_for_exp(p: &Proc, base: usize, exp: i32) -> i32 {
    let th: Vec<i32> = (0..8)
        .map(|i| p.u32_at(base + SPEED_THRESH_OFF + i * 4) as i32)
        .collect();
    let l = th.iter().position(|&t| exp >= t).unwrap_or(7);
    (SPEED_BASE[l] + (exp - th[l]) / SPEED_DENOM[l]).max(SPEED_MIN)
}

/// 球種的球威/控球/變化幅度是 **G~S（0~7）**，用的是另一組基礎值表
/// （`exe+0x841DBF0+0x20` ＝ `7,6,5,4,3,2,1,0`），所以等級 g 需要的經驗值
/// 就是門檻表的第 `7−g` 項。實測吻合：`51000`→S、`400`→F、`100`→G。
pub fn exp_for_ball_grade(g: u8) -> i32 {
    GROWTH_THRESHOLDS[7 - g.min(7) as usize]
}

/// 寫某一項能力值，**並同步寫它的成長經驗值**。
///
/// 明星選手模式只寫能力值的話，下次結算就會依經驗值算回去
/// （畫面還會顯示「力量已下降 N 了！」）。找不到經驗值結構（＝栄冠模式）就只寫能力值。
pub fn write_stat_synced(p: &Proc, obj: usize, idx: usize, v: u8) -> bool {
    let ok = write_stat(p, obj, idx, v);
    if let Some(g) = growth_struct_for(p, obj) {
        let e = STAT_TO_EXP[idx];
        if e >= 0 {
            let exp = exp_for_stat(v as i32);
            p.write(g + GROWTH_EXP_OFF + e as usize * 4, &exp.to_le_bytes());
        }
    }
    ok
}

/// 球速/耐力（packed）＋ 同步**兩者**的經驗值。
///
/// 兩邊用不同的換算表：耐力跟能力值同一組（`exp_for_stat`），
/// 球速有自己的基礎值/門檻/分母（`exp_for_speed`，門檻在結構 `+0x158`）。
///
/// ⚠ 球速要超過 175 得先 patch **兩處**程式碼上限（`SPEED_CAP_AOB` / `SPEED_CAP_AOB2`）。
pub fn write_pack_synced(p: &Proc, obj: usize, speed: u16, stam: u16, hi: u16) -> bool {
    let ok = write_pack(p, obj, speed, stam, hi);
    if let Some(g) = growth_struct_for(p, obj) {
        p.write(g + GROWTH_EXP_OFF + EXP_IDX_STAMINA * 4,
                &exp_for_stat(stam as i32).to_le_bytes());
        p.write(g + GROWTH_EXP_OFF + EXP_IDX_SPEED * 4,
                &exp_for_speed(p, g, speed as i32).to_le_bytes());
    }
    ok
}

/// 投手守備適性 ＋ 同步經驗值
pub fn write_def_synced(p: &Proc, obj: usize, v: u8) -> bool {
    let ok = p.write(obj + OFF_DEF, &[v]);
    if let Some(g) = growth_struct_for(p, obj) {
        let exp = exp_for_stat(v as i32);
        p.write(g + GROWTH_EXP_OFF + EXP_IDX_PITCHER_DEF * 4, &exp.to_le_bytes());
    }
    ok
}

/// 8 個野手守位之一（`+0x18+i`）＋ 同步經驗值（`+0x68+i*4`）。
/// ⚠ 只寫顯示值撐不住：沒練的守位看起來正常，**一旦在遊戲內練它就會被算回 G**。
pub fn write_field_synced(p: &Proc, obj: usize, i: usize, v: u8) -> bool {
    if i >= GROWTH_FIELD_N {
        return false;
    }
    let ok = p.write(obj + 0x18 + i, &[v]);
    if let Some(g) = growth_struct_for(p, obj) {
        let exp = exp_for_stat(v as i32);
        p.write(g + GROWTH_FIELD_OFF + i * 4, &exp.to_le_bytes());
    }
    ok
}

/// 球種 ＋ 同步該 slot 的三格經驗值（球威/控球/變化幅度各自照等級換算）。
/// 直球系（方向5）沒有變化幅度，第三格不寫。
pub fn write_ball_synced(p: &Proc, obj: usize, slot: usize, b: &Ball) -> bool {
    let ok = write_ball(p, obj, slot, b);
    if b.id == BALL_EMPTY {
        return ok; // 清空 slot 就不要動經驗值（寫進去＝給不存在的項目經驗值）
    }
    if let Some(g) = growth_struct_for(p, obj) {
        let off = g + GROWTH_BALL_OFF + slot * GROWTH_BALL_STRIDE;
        p.write(off, &exp_for_ball_grade(b.power).to_le_bytes());
        p.write(off + 4, &exp_for_ball_grade(b.control).to_le_bytes());
        if slot % 6 != 5 {
            p.write(off + 8, &exp_for_ball_grade(b.move_).to_le_bytes());
        }
    }
    ok
}

/// 指定「目標能力值」寫入經驗值（不是無腦灌滿）。
///
/// `+0x5C`（球速/耐力）走另一套換算（223600→175km/h，不 clamp 在 99），
/// 沒有反解公式，所以維持灌到它自己的上限。
pub fn set_growth_target(p: &Proc, base: usize, target: i32) -> bool {
    if !growth_struct_ok(p, base) {
        return false;
    }
    let exp = exp_for_stat(target);
    let ok_stat = (0..GROWTH_EXP_N).all(|i| {
        // i==7 ＝ +0x5C 球速：走另一套換算, 沒有反解 → 灌滿。其餘（含 i==8 耐力）照目標值
        let v = if i == EXP_IDX_SPEED { GROWTH_EXP_MAX } else { exp };
        p.write(base + GROWTH_EXP_OFF + i * 4, &v.to_le_bytes())
    });
    // 8 個野手守位同樣照目標值換算
    let ok_field = (0..GROWTH_FIELD_N)
        .all(|i| p.write(base + GROWTH_FIELD_OFF + i * 4, &exp.to_le_bytes()));
    ok_stat && ok_field
}

/// 明星選手物件常出現的區間，**依序**試，命中就不再往下掃。
///
/// | 觀測 | 區間 |
/// |---|---|
/// | 2026-08-27 更新後 | `0x1_0000_0000`~`0x1_3000_0000`（實測結構在 `0x113e`／`0x113f`） |
/// | 更新前 | `0xd000_0000`~`0xf000_0000`（實測 `0xd7`~`0xee`） |
///
/// ⚠ 這只是加速用的猜測，**掃不到一定要退回全記憶體** ——
/// 熱區失準時症狀不是「找不到」而是「變慢」（2026-08-29 從 1.4 秒變成 34 秒），
/// 很容易被當成正常而放著不管。
pub const GROWTH_HOT_ZONES: [(usize, usize); 2] =
    [(0x1_0000_0000, 0x1_3000_0000), (0xd000_0000, 0xf000_0000)];

/// 先掃熱區，沒有才全掃。給「只找主角、不要等 100 秒全掃」用。
pub fn find_growth_structs_fast(p: &Proc) -> Vec<usize> {
    let all = p.writable_ranges();
    for (lo, hi) in GROWTH_HOT_ZONES {
        let hot: Vec<(usize, usize)> = all
            .iter()
            .copied()
            .filter(|&(b, s)| b + s > lo && b < hi)
            .collect();
        if hot.is_empty() {
            continue;
        }
        let r = find_growth_in(p, &hot);
        if !r.is_empty() {
            return r;
        }
    }
    find_growth_in(p, &all)
}

/// 全記憶體找出所有成長經驗值結構（選手物件位址不明時的後備手段）。
pub fn find_growth_structs(p: &Proc) -> Vec<usize> {
    find_growth_in(p, &p.writable_ranges())
}

fn find_growth_in(p: &Proc, ranges: &[(usize, usize)]) -> Vec<usize> {
    const CHUNK: usize = 64 << 20;
    let pat: Vec<u8> = GROWTH_THRESHOLDS.iter().flat_map(|v| v.to_le_bytes()).collect();
    let mut out = Vec::new();
    for &(base, size) in ranges {
        let mut off = 0usize;
        while off < size {
            let want = (size - off).min(CHUNK + pat.len());
            if let Some(buf) = p.read(base + off, want) {
                if buf.len() >= pat.len() {
                    for q in 0..=buf.len() - pat.len() {
                        if buf[q] == pat[0] && buf[q..q + pat.len()] == pat[..] {
                            let a = base + off + q;
                            if a >= GROWTH_THRESH_OFF {
                                let b = a - GROWTH_THRESH_OFF;
                                if growth_struct_ok(p, b) {
                                    out.push(b);
                                }
                            }
                        }
                    }
                }
            }
            off += CHUNK;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

// ─────────────────────────────────────────────── 全記憶體掃描選手物件

const BALL_MAX_ID: u8 = 45;

/// 球種陣列本身就是很強的簽章。實測每位選手 slot5（方向5／直球系）一定非空。
/// ⚠ 全零區塊會變成「12 個 ID0」而誤判，所以另外要求「至少一格是 37」
/// 且「第一顆空的話第二顆也必須空」。
fn ball_sig_ok(b: &[u8]) -> bool {
    if b[15] == BALL_EMPTY || b[15] > BALL_MAX_ID {
        return false;
    }
    let mut has_empty = false;
    let mut has_power = false;
    for k in 0..N_BALL {
        let (id, pw, ct) = (b[k * 3], b[k * 3 + 1], b[k * 3 + 2]);
        if id > BALL_MAX_ID || pw > 63 || ct > 7 {
            return false;
        }
        if id == BALL_EMPTY {
            if pw != 0 || ct != 0 {
                return false;
            }
            has_empty = true;
        }
        if pw != 0 {
            has_power = true;
        }
    }
    // ⚠ 曾經還要求「至少一格球威非 0」—— 那條會把**野手全部濾掉**：
    //   野手只有一顆 G 級直球，球威就是 0（實測栄冠 30 人裡的野手都是）。
    //   全零區塊本來就被 has_empty（至少一格 37）擋掉了，不需要靠球威。
    let _ = has_power;
    if !has_empty {
        return false;
    }
    for k in 0..6 {
        if b[k * 3] == BALL_EMPTY && b[(k + 6) * 3] != BALL_EMPTY {
            return false;
        }
    }
    true
}

/// 全記憶體掃出所有選手物件（給沒有指標鏈的模式用，例如明星選手）。
/// progress: (已掃 MB, 總 MB)
pub fn scan_players(p: &Proc, progress: impl FnMut(usize, usize)) -> Vec<Player> {
    let ranges = p.writable_ranges();
    scan_players_in(p, &ranges, progress)
}

pub fn scan_players_in(
    p: &Proc,
    ranges: &[(usize, usize)],
    mut progress: impl FnMut(usize, usize),
) -> Vec<Player> {
    const CHUNK: usize = 64 << 20;
    const OVER: usize = 0x1000;
    let total: usize = ranges.iter().map(|r| r.1).sum();
    let mut done = 0usize;
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();

    for &(base, size) in ranges {
        let mut off = 0usize;
        while off < size {
            let want = (size - off).min(CHUNK + OVER);
            if let Some(buf) = p.read(base + off, want) {
                if buf.len() > 36 + OFF_BALL {
                    let lim = buf.len() - 36;
                    for q in OFF_BALL..lim {
                        if !ball_sig_ok(&buf[q..q + 36]) {
                            continue;
                        }
                        let ob = q - OFF_BALL;
                        if !buf[ob + OFF_STATS..ob + OFF_STATS + 8]
                            .iter()
                            .all(|&v| (1..=127).contains(&v))
                        {
                            continue;
                        }
                        let addr = base + off + ob;
                        // 一次讀完整個物件再解析 —— 舊版是先 read_name 再逐欄位讀，
                        // 每個候選要 ~25 次 ReadProcessMemory
                        let Some(raw) = p.read(addr, PLAYER_READ) else { continue };
                        if !sane_name(&name_from(&raw)) {
                            continue;
                        }
                        if let Some(pl) = Player::parse(&raw, addr) {
                            let key = format!(
                                "{}|{:?}|{}|{}",
                                pl.name, pl.stats, pl.speed,
                                pl.balls.iter()
                                    .map(|b| format!("{},{},{}", b.id, b.power, b.control))
                                    .collect::<Vec<_>>().join("/")
                            );
                            if seen.insert(key) {
                                out.push(pl);
                            }
                        }
                    }
                }
            }
            off += CHUNK;
            done += CHUNK.min(size);
            progress(done >> 20, total >> 20);
        }
    }
    drop_inner_copies(&mut out);
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// 丟掉「同一筆記錄的第二份子記錄」（位址剛好差 [`REC_INNER`] 且同名）。
///
/// 掃描器會把它也認成一位選手，於是每個人都多一份 —— 實測 3261 人裡有 744 份。
/// 以遊戲畫面的球速/耐力對照 12 位選手，**第一份才是畫面在讀的，第二份一律是舊值**。
pub fn drop_inner_copies(v: &mut Vec<Player>) {
    let by: std::collections::HashMap<usize, String> =
        v.iter().map(|p| (p.addr, p.name.clone())).collect();
    v.retain(|p| {
        p.addr < REC_INNER || by.get(&(p.addr - REC_INNER)).is_none_or(|n| *n != p.name)
    });
}

// ─────────────────────────────────────────────── 原創球種庫（origlib.json）

#[derive(Clone, Debug)]
pub struct LibEntry {
    pub name: String,
    pub slot: usize,
    pub dir: usize,
    pub base: u8,
    pub kind: String,
    pub holder: String,
    pub raw: Vec<u8>,
}

/// 寫入捕手配球（0=G … 7=S）。同一 byte 的其他 bit 要保留，所以是讀-改-寫。
pub fn write_catcher(p: &Proc, obj: usize, v: u8) -> bool {
    let cur = p.u8_at(obj + OFF_CATCH);
    let nv = (cur & !(7 << CATCH_SHIFT)) | ((v & 7) << CATCH_SHIFT);
    p.write(obj + OFF_CATCH, &[nv])
}

/// 寫入栄冠「打擊積極性」等級（0=G … 6=A；沒有 S）。
///
/// 實測對照：
/// G: A5B=00 / 10AE=07
/// F: A5B=01 / 10AE=06
/// E: A5B=02 / 10AE=05
/// D: A5B=03 / 10AE=04
/// C: A5B=04 / 10AE=03
/// B: A5B=05 / 10AE=02
/// A: A5B=06 / 10AE=01
///
/// 兩處都只改 low3；其他未知旗標全部保留。
pub fn write_batting_aggression(p: &Proc, obj: usize, grade: u8) -> bool {
    if grade > 6 {
        return false;
    }

    // ⚠ 不寫 OFF_BATTING_AGGRESSION_SYNC —— 實測是副本（見常數處的說明）
    let a = p.u8_at(obj + OFF_BATTING_AGGRESSION);
    let na = (a & !0x07) | (grade & 0x07);
    p.write(obj + OFF_BATTING_AGGRESSION, &[na])
}

/// 寫入栄冠「選球眼」等級（0=G … 6=A；沒有 S）。
///
/// 實測對照：
/// G: A53=00 / 10AA=07
/// F: A53=08 / 10AA=06
/// E: A53=10 / 10AA=05
/// D: A53=18 / 10AA=04
/// C: A53=20 / 10AA=03
/// B: A53=28 / 10AA=02
/// A: A53=30 / 10AA=01
///
/// +0xA53 只改 bit3~5，+0x10AA 只改 low3；其他未知旗標全部保留。
pub fn write_plate_discipline(p: &Proc, obj: usize, grade: u8) -> bool {
    if grade > 6 {
        return false;
    }

    // ⚠ 不寫 OFF_PLATE_DISCIPLINE_SYNC —— 實測是副本
    let a = p.u8_at(obj + OFF_PLATE_DISCIPLINE);
    let na = (a & !PLATE_DISCIPLINE_MASK) | ((grade & 7) << PLATE_DISCIPLINE_SHIFT);
    p.write(obj + OFF_PLATE_DISCIPLINE, &[na])
}

/// 寫入栄冠「人氣」旗標。
///
/// 三位不同球員以書本取得人氣時都觀察到：
/// * `+0xA30 low3: 1 -> 2`
/// * `+0x10B6 low3: 1 -> 2`
///
/// 手動切換 `+0xA30 low3` 已驗證 `1=人氣消失`、`2=人氣出現`；
/// `+0x10B6` 單獨切換不影響即時顯示，但可能是成長／結算同步欄位。
/// 為了讓推進日期時的遊戲結算狀態也一致，兩處同步寫入。
/// `+0xA30` 的 bit3~6 同時存主要守備位置，所以兩處都只做讀-改-寫 low3。
pub fn write_popularity(p: &Proc, obj: usize, on: bool) -> bool {
    let v = if on { POPULARITY_ON } else { POPULARITY_OFF };

    let cur = p.u8_at(obj + OFF_POPULARITY);
    let nv = (cur & !POPULARITY_MASK) | v;

    let sync_cur = p.u8_at(obj + OFF_POPULARITY_SYNC);
    let _ = sync_cur; // ⚠ 不寫 OFF_POPULARITY_SYNC —— 實測是副本
    p.write(obj + OFF_POPULARITY, &[nv])
}

/// 寫入九宮格。只動低 27 bits，高 5 bits（別的欄位）原樣保留。
pub fn write_zone(p: &Proc, obj: usize, z: &[i8; ZONE_N]) -> bool {
    let mut raw = p.u32_at(obj + OFF_ZONE);
    for i in 0..ZONE_N {
        raw = zone_set(raw, i, z[i]);
    }
    p.write(obj + OFF_ZONE, &raw.to_le_bytes())
}

/// 從已載入的選手身上蒐集原創球種記錄，依名稱去重後併進球種庫。回傳新增筆數。
///
/// 發布用的 `origlib.json` 只附官方球種（人人都有）；自訂球種是各人存檔獨有的，
/// 靠這個函式從自己的遊戲裡自動補進來。
pub fn merge_recs_into_lib(lib: &mut Vec<LibEntry>, players: &[Player]) -> usize {
    let mut added = 0;
    for pl in players {
        for r in &pl.recs {
            // slot 12 ＝ 該筆未使用；名稱有替換字元代表讀到的不是有效記錄
            if r.slot as usize >= N_BALL
                || r.raw.len() != REC
                || r.name.is_empty()
                || r.name.contains('\u{FFFD}')
                || lib.iter().any(|e| e.name == r.name)
            {
                continue;
            }
            lib.push(LibEntry {
                name: r.name.clone(),
                slot: r.slot as usize,
                dir: r.slot as usize % 6,
                base: r.base,
                kind: if r.official { "官方" } else { "自訂" }.to_string(),
                holder: pl.name.clone(),
                raw: r.raw.clone(),
            });
            added += 1;
        }
    }
    if added > 0 {
        lib.sort_by(|a, b| (a.dir, a.name.clone()).cmp(&(b.dir, b.name.clone())));
    }
    added
}

/// 把球種庫寫回 JSON（欄位與 [`load_lib`] 對應）
pub fn save_lib(path: &std::path::Path, lib: &[LibEntry]) -> Result<(), String> {
    let arr: Vec<serde_json::Value> = lib
        .iter()
        .map(|e| {
            let hex: String = e.raw.iter().map(|b| format!("{b:02x}")).collect();
            serde_json::json!({
                "name": e.name, "slot": e.slot, "dir": e.dir,
                "base": e.base, "kind": e.kind, "holder": e.holder, "hex": hex,
            })
        })
        .collect();
    let txt = serde_json::to_string_pretty(&serde_json::Value::Array(arr))
        .map_err(|e| e.to_string())?;
    std::fs::write(path, txt).map_err(|e| format!("寫入 {} 失敗：{e}", path.display()))
}

/// 依序尋找 `origlib.json`：exe 同層（release 壓縮檔的擺法）→ 倉庫根目錄
/// （從 `target/release/` 執行時）→ `memtool/`（開發樹的舊位置）→ 工作目錄。
/// 都找不到就回傳第一個候選，讓錯誤訊息指向最合理的擺放位置。
pub fn origlib_path() -> std::path::PathBuf {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_default();
    // ⚠ 層數：exe 在 <repo>/target/release/ → `../..` 才是倉庫根，`../../..` 是倉庫的上一層。
    //   一度把倉庫根寫成 `../../..`，clone 下來自己編譯的人會整個找不到球種庫。
    let cands = [
        exe_dir.join("origlib.json"),
        exe_dir.join("../../origlib.json"),
        exe_dir.join("../../../memtool/origlib.json"),
        std::path::PathBuf::from("origlib.json"),
    ];
    for c in &cands {
        if c.exists() {
            return c.clone();
        }
    }
    cands.into_iter().next().unwrap()
}

/// 蒐集到的球種**一律存到 exe 同層**，不要寫回載入來源。
///
/// 從開發樹執行時 [`origlib_path`] 會找到倉庫根目錄那份（受 git 追蹤，只放官方球種），
/// 寫回去會讓自己的自訂球種混進版控。存到 exe 同層則落在 `target/` 裡，
/// 而且下次啟動時因為 exe 同層是第一順位，會優先讀到這份較完整的。
pub fn origlib_save_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("origlib.json")))
        .unwrap_or_else(|| std::path::PathBuf::from("origlib.json"))
}

pub fn load_lib(path: &std::path::Path) -> Vec<LibEntry> {
    let txt = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let v: serde_json::Value = match serde_json::from_str(&txt) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for e in v.as_array().unwrap_or(&Vec::new()) {
        let hex = e["hex"].as_str().unwrap_or("");
        let raw: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
            .collect();
        if raw.len() != REC {
            continue;
        }
        out.push(LibEntry {
            name: e["name"].as_str().unwrap_or("").to_string(),
            slot: e["slot"].as_u64().unwrap_or(0) as usize,
            dir: e["dir"].as_u64().unwrap_or(0) as usize,
            base: e["base"].as_u64().unwrap_or(0) as u8,
            kind: e["kind"].as_str().unwrap_or("").to_string(),
            holder: e["holder"].as_str().unwrap_or("").to_string(),
            raw,
        });
    }
    out.sort_by(|a, b| (a.dir, a.name.clone()).cmp(&(b.dir, b.name.clone())));
    out
}

/// 隊伍 ID ＝ `+0xA16`（`+0xA17` 是同值的第二份）。明星選手模式用它把選手分隊。
///
/// ⚠ **不要用「位址連續段」分隊。** 隊伍名單確實是 stride `0x30D8` 的連續陣列，
/// 但掃描器會漏掉少數選手，把同一隊切成好幾段（實測 1474 人只有 288 人落在
/// ≥5 人的連續段裡，而且相鄰兩段其實是同一隊）。用這個 ID 才可靠。
///
/// ⚠ 記憶體裡**沒有** ID→隊名的對照表 —— 隊名散在無索引的固定槽字串池裡，
/// 跟能力名稱那次一樣查不到。所以隊名由使用者自己命名並存到 `teams.json`。
pub const OFF_TEAM: usize = 0xA16;

/// 同一筆隊伍陣列記錄裡的**第二份子記錄**的位移。
///
/// 掃描器會把它也認成一位選手，於是每個人都多出一份。實測（12 位以遊戲畫面
/// 的球速/耐力對照）**第一份才是畫面在讀的，第二份一律是舊值**，所以直接丟掉。
/// 姓名字串也是這個間距（`+0x914` 與 `+0x25C4`），可以互相印證。
pub const REC_INNER: usize = 0x1CB0;

/// 已確認的隊伍 ID → 隊名（用遊戲畫面的名單逐隊對照出來的）。
/// 使用者可以用 `teams.json` 覆寫或補充。
pub const DEFAULT_TEAMS: [(u8, &str); 38] = [
    // ── NPB 12 球團（用遊戲畫面的名單逐隊對照確認）
    (0, "巨人"),
    (1, "中日"),
    (2, "廣島"),
    (3, "養樂多"),
    (4, "DeNA"),
    (5, "阪神"),
    (6, "樂天"),
    (7, "日本火腿"),
    (8, "西武"),
    (9, "歐力士"),
    (10, "羅德"),
    (11, "軟銀"),
    // ── 2026 WBC 的 20 支國家隊佔 31~52。已知 32=韓國、52=台灣正好是頭尾，
    //    中間 35~51 由選手姓名辨識（Judge/Skenes=美國、Soto/Machado=多明尼加…）。
    //    ⚠ 這一段**不是 MLB 球團**，一度誤判過。
    (31, "日本代表"),
    (32, "韓國"),
    (35, "古巴"),
    (36, "墨西哥"),
    (37, "澳洲"),
    (38, "尼加拉瓜"),
    (39, "美國"),
    (40, "加拿大"),
    (41, "委內瑞拉"),
    (42, "義大利"),
    (43, "多明尼加"),
    (44, "波多黎各"),
    (45, "巴拿馬"),
    (46, "荷蘭"),
    (47, "哥倫比亞"),
    (48, "以色列"),
    (49, "捷克"),
    (50, "英國"),
    (51, "巴西"),
    (52, "台灣"),
    // ── 歷屆 WBC 日本代表：只收「優勝屆」＋現屆（2013/2017 沒奪冠所以缺）。
    //    這個規律本身也反過來佐證了四隊的判定。
    (53, "日本代表 2006"),
    (54, "日本代表 2009"),
    (55, "日本代表 2023"),
    (56, "日本代表 2026"),
    (65, "栄冠（自校）"),
    (66, "選手池（非球隊）"),
    // ⚠ ID 57 刻意不寫死：28 人裡 22 位在真實棒球界查無此人，混著 4 位現任
    //    NPB 監督／教練（新井貴浩、阿部慎之助…），性質不明。留給使用者自己命名。
];
/// `teams.json`（ID→隊名）跟 `origlib.json` 一樣放 exe 同層
pub fn teams_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("teams.json")))
        .unwrap_or_else(|| std::path::PathBuf::from("teams.json"))
}

pub fn load_teams(path: &std::path::Path) -> std::collections::HashMap<u8, String> {
    let mut out: std::collections::HashMap<u8, String> = DEFAULT_TEAMS
        .iter()
        .map(|&(k, v)| (k, v.to_string()))
        .collect();
    let Ok(txt) = std::fs::read_to_string(path) else { return out };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&txt) else { return out };
    for (k, val) in v.as_object().into_iter().flatten() {
        if let (Ok(id), Some(s)) = (k.parse::<u8>(), val.as_str()) {
            if !s.is_empty() {
                out.insert(id, s.to_string());
            }
        }
    }
    out
}

pub fn save_teams(
    path: &std::path::Path,
    m: &std::collections::HashMap<u8, String>,
) -> Result<(), String> {
    let mut keys: Vec<_> = m.keys().copied().collect();
    keys.sort();
    let obj: serde_json::Map<String, serde_json::Value> = keys
        .iter()
        .map(|k| (k.to_string(), serde_json::Value::String(m[k].clone())))
        .collect();
    let txt = serde_json::to_string_pretty(&serde_json::Value::Object(obj))
        .map_err(|e| e.to_string())?;
    std::fs::write(path, txt).map_err(|e| format!("寫入 {} 失敗：{e}", path.display()))
}

// ─────────────────────────────────────────────── 栄冠：野手風格（打擊積極性／選球眼）

/// 打擊積極性顯示等級：`+0xA5B` low3。
/// 實測 0..6 分別為 G/F/E/D/C/B/A，沒有 S。
pub const OFF_BATTING_AGGRESSION: usize = 0xA5B;

/// 打擊積極性同步欄位：`+0x10AE` low3。
/// 實測 G/F/E/D/C/B/A 對應 7/6/5/4/3/2/1。
/// ⚠ **打擊積極性的副本，遊戲既不讀也不回寫 —— 不要寫它。**
/// 2026-08-29 實測：只寫主值、這裡完全不動，畫面照樣正確改變。
/// 值是主值的反向編碼（`7 - grade`），保留常數只為記下「這裡有一份」。
pub const OFF_BATTING_AGGRESSION_SYNC: usize = 0x10AE;

/// 選球眼顯示等級：`+0xA53` bit3~5。
/// 實測 0..6 分別為 G/F/E/D/C/B/A，沒有 S。
pub const OFF_PLATE_DISCIPLINE: usize = 0xA53;
pub const PLATE_DISCIPLINE_SHIFT: u32 = 3;
pub const PLATE_DISCIPLINE_MASK: u8 = 0x38;

/// 選球眼同步欄位：`+0x10AA` low3。
/// 實測 G/F/E/D/C/B/A 對應 7/6/5/4/3/2/1。
/// ⚠ **選球眼的副本，遊戲既不讀也不回寫 —— 不要寫它。**
/// 2026-08-29 實測：只寫主值、這裡完全不動，畫面照樣正確改變。
/// 值是主值的反向編碼（`7 - grade`），保留常數只為記下「這裡有一份」。
pub const OFF_PLATE_DISCIPLINE_SYNC: usize = 0x10AA;

/// 人氣直接顯示欄位與主要守備位置共用 `+0xA30`。
/// low3 實測：1=無人氣、2=有人氣；bit3~6 是主要守備位置，絕對不能整 byte 覆蓋。
pub const OFF_POPULARITY: usize = OFF_POS;
pub const POPULARITY_MASK: u8 = 0x07;
pub const POPULARITY_OFF: u8 = 0x01;
pub const POPULARITY_ON: u8 = 0x02;

/// 人氣同步／結算欄位：`+0x10B6` low3。
/// 三位球員以書本取得人氣時皆觀察到 1 -> 2；單獨改此欄不影響即時顯示。
/// ⚠ **人氣的副本，遊戲既不讀也不回寫 —— 不要寫它。**
/// 2026-08-29 實測：只寫主值、這裡完全不動，畫面照樣正確改變。
/// 值是主值的反向編碼（`7 - grade`），保留常數只為記下「這裡有一份」。
pub const OFF_POPULARITY_SYNC: usize = 0x10B6;

// ─────────────────────────────────────────────── 栄冠：打擊姿勢 / 打球型態

/// 打擊姿勢主欄位：`+0x2D` 的 low 2 bits。
/// 實測 high bits（例如 0x04）不影響這組能力顯示，所以寫入時保留它們。
pub const OFF_BATTING_STYLE: usize = 0x2D;

/// 打擊姿勢同步欄位：`+0xFB6` 的 low 3 bits。
/// 目前只確認 0..6；其餘 high bits 保留，避免破壞未知旗標。
/// ⚠ **彈道的副本，遊戲既不讀也不回寫** —— 保留只為了記下「這裡有一份」。
/// 2026-08-29 實測確認（見 [`write_batting_style`]）。副本區的偏移規律是 `+0x114`
/// （`0xE90`→`0xFA4`、`0xEA0`→`0xFB4`），`0xFB6` 就在捕手配球副本的隔壁。
/// **不要拿它判讀，也不要寫它。**
pub const OFF_BATTING_SYNC: usize = 0xFB6;

pub const BATTING_STYLE_UNKNOWN: u8 = 0xFF;
pub const BATTING_STYLE_NAMES: [&str; 7] = [
    "滾地球型", "低仰角", "中仰角", "高仰角", "平飛球強襲", "力量型打者", "全壘打藝術家",
];

/// (2C bit7, 2D low2, FB6 low3)。
/// 2026-08-23 以兩位栄冠球員交叉驗證：低仰角／力量型打者／全壘打藝術家完全一致；
/// 第一位另完整測得全部 7 種。
pub const BATTING_STYLE_RAW: [(bool, u8, u8); 7] = [
    (false, 0, 0), // 滾地球型
    (true,  0, 1), // 低仰角
    (true,  1, 3), // 中仰角
    (false, 2, 4), // 高仰角
    (false, 1, 2), // 平飛球強襲
    (true,  2, 5), // 力量型打者
    (false, 3, 6), // 全壘打藝術家
];

pub fn batting_style_name(v: u8) -> &'static str {
    BATTING_STYLE_NAMES.get(v as usize).copied().unwrap_or("未知組合")
}

/// 從三個實際欄位判定目前打擊姿勢；不認識的組合回 None。
/// ⚠ **只看 `0x2C` bit7 與 `0x2D` low2，`fb6` 參數保留但不參與判斷。**
///
/// 2026-08-29 實測：只寫 `0x2D`（`0xFB6` 故意不動）→ 遊戲畫面就變了，
/// 而且事後回讀 `0xFB6` **仍是舊值**，遊戲並沒有回寫同步它。
/// 那兩欄的 7 種組合本來就互不重複，足以單獨決定彈道。
///
/// 拿 `fb6` 一起比對會有實害：外部只改了 `0x2D` 時，三元組會落在表外
/// → 回傳 None → UI 顯示「未知組合」，但遊戲其實已經生效了。
pub fn batting_style_from_raw(c2c: u8, c2d: u8, _fb6: u8) -> Option<u8> {
    let key = (c2c & 0x80 != 0, c2d & 0x03);
    BATTING_STYLE_RAW.iter().position(|&(b, d, _)| (b, d) == key).map(|i| i as u8)
}

/// 寫入彈道（弾道）。`+0x2C` 只動 bit7（bit4~6 是捕手配球）、`+0x2D` 只動 low2，
/// 兩欄都是 read-modify-write，保留各自未確認的其他 bits。
///
/// ⚠ **不寫 `+0xFB6`。** 2026-08-29 兩位選手交叉實測：
/// 毛利只寫 `0x2D`（`0xFB6` 保持 0）、中尾三處都寫，**兩人的畫面都正確改變**，
/// 而且毛利的 `0xFB6` 事後回讀仍是 0 —— 遊戲既不讀它、也不回寫它。
///
/// `0xFB6` 落在已知的副本區（`0xE90`→`0xFA4`、`0xEA0`→`0xFB4` 都是 `+0x114`，
/// 而 `0xFB6` 就在捕手配球副本 `0xFB4` 隔壁）。寫副本沒有作用，
/// 而本專案已經在副本上栽過五次，沒必要多碰一個已知的副本位址。
pub fn write_batting_style(p: &Proc, obj: usize, style: u8) -> bool {
    let Some(&(bit7, d, _sync)) = BATTING_STYLE_RAW.get(style as usize) else {
        return false;
    };

    let c2c = p.u8_at(obj + OFF_CATCH);
    let n2c = if bit7 { c2c | 0x80 } else { c2c & !0x80 };

    let c2d = p.u8_at(obj + OFF_BATTING_STYLE);
    let n2d = (c2d & !0x03) | (d & 0x03);

    p.write(obj + OFF_CATCH, &[n2c]) && p.write(obj + OFF_BATTING_STYLE, &[n2d])
}

/// 捕手配球（G~S）＝ `+0x2C` 的 **bit4~6**（3 bits，0=G … 7=S）。
///
/// ⚠ 同一個 byte 的其他 bit 是別的旗標（實測 bit7 大多為 1），寫入務必讀-改-寫。
/// ⚠ 副本在 `+0xEA0`／`+0xFB4`（整個 byte）—— 那兩處在已知的能力值副本區裡，
///   所以真值取這裡的 `+0x2C`（與守備適性／球速同一個已驗證的真值區）。
pub const OFF_CATCH: usize = 0x2C;
pub const CATCH_SHIFT: u32 = 4;

/// 擅長・不擅長球路的九宮格 ＝ `+0xA50` 起 **9 個 3-bit 欄位**（整體 little-endian u32）。
///
/// 值是 **3-bit 二補數**（跟特殊能力等級同一套）：`0..3` ＝ `0..+3`、`5/6/7` ＝ `-3/-2/-1`。
/// 順序就是畫面的列優先（左上 → 右下），不用重排。
/// 27 bits 用掉、高 5 bits 是別的東西，所以要整個 u32 讀-改-寫。
pub const OFF_ZONE: usize = 0xA50;
pub const ZONE_N: usize = 9;

pub fn zone_get(raw: u32, i: usize) -> i8 {
    let v = ((raw >> (3 * i)) & 7) as i8;
    if v >= 4 { v - 8 } else { v }
}

pub fn zone_set(raw: u32, i: usize, v: i8) -> u32 {
    let e = (v.clamp(-3, 3) as u32) & 7;
    (raw & !(7 << (3 * i))) | (e << (3 * i))
}

/// 守備位置（畫面上姓名右邊那個圖標）。
///
/// ⚠ **不是**守備適性的最大值 —— 這是獨立欄位。實測川俣的遊擊 97 最高，
/// 遊戲仍標 2B 且守備欄顯示二壘的 47。栄冠 30 人全部一致。
/// 編碼 ＝ 守備適性陣列（捕/一/二/三/遊/左/中/右）的順序前面加上投手。
///
/// 存在 `+0xA30` 的 **bit3~6**（4 bits），就在九宮格 `+0xA50` 旁邊的同一塊 bitfield 區。
///
/// ⚠ **不要用 `+0xEB6`**（曾經用過）。那個在栄冠模式剛好也對，但它落在能力值副本區
/// （`0xE90`/`0xFA4`），到了明星選手模式整個是別的東西 —— 實測 3261 位選手的值域
/// 是 0~202，位置 1~8 幾乎不出現，清單全變成「?」。
/// `+0xA30` 兩個模式都正確（栄冠 20 位畫面已知位置全中）。
pub const OFF_POS: usize = 0xA30;
pub const POS_SHIFT: u32 = 3;

/// 讀出守備位置代號（0=P … 8=RF）
pub fn pos_of(p: &Proc, obj: usize) -> u8 {
    ((p.u16_at(obj + OFF_POS) >> POS_SHIFT) & 0xF) as u8
}

pub const POS_NAMES: [&str; 9] = ["P", "C", "1B", "2B", "3B", "SS", "LF", "CF", "RF"];

/// 寫入主要守備位置（0=P … 8=RF）。
/// `+0xA30` 只有 bit3~6 是位置，其他 bit 屬於同一區塊的其他欄位，必須保留。
/// 超出已確認的 0..=8 一律拒絕，避免把未定義位置寫進存檔物件。
pub fn write_pos(p: &Proc, obj: usize, v: u8) -> bool {
    if v as usize >= POS_NAMES.len() {
        return false;
    }
    let cur = p.u16_at(obj + OFF_POS);
    let mask = 0xFu16 << POS_SHIFT;
    let nv = (cur & !mask) | (((v as u16) << POS_SHIFT) & mask);
    p.write(obj + OFF_POS, &nv.to_le_bytes())
}

/// 介面滑桿的上限 ＝ 遊戲實際承認的上限。
/// 球速 175：patch 掉程式碼上限後資料能到 207，但**實戰投出來仍然是 175**，沒有意義。
/// 能力值 99：換算函式自己就 `min(…, 0x63)`。
pub const SPEED_UI_MAX: u16 = 175;
pub const STAT_UI_MAX: u8 = 99;

/// 位置代號；超出範圍回 `"?"`（其他模式不保證這個欄位有效）
pub fn pos_name(v: u8) -> &'static str {
    POS_NAMES.get(v as usize).copied().unwrap_or("?")
}

/// 8 個野手守位的名稱（`+0x18..0x1F` 的順序）
pub const FIELD_NAMES: [&str; GROWTH_FIELD_N] =
    ["捕手", "一壘手", "二壘手", "三壘手", "游擊手", "左外野手", "中外野手", "右外野手"];

// ─────────────────────────────────────────────── 測試（不用開遊戲）

#[cfg(test)]
mod player_tests {
    use super::*;

    /// 造一個合法的選手物件 bytes，每個欄位放不同的值。
    ///
    /// ⚠ 這個測試存在的理由：`Player::parse` 是把「逐欄位 ReadProcessMemory」
    /// 改寫成「一次讀完再切」，最容易犯的錯就是 offset 打錯一位 ——
    /// 而那種錯在真實記憶體上會讀出「看起來很合理」的別人的值。
    fn mkbuf() -> Vec<u8> {
        let mut b = vec![0u8; PLAYER_READ];
        for (i, v) in [3u8, 1, 4, 1, 5, 9, 2, 6].iter().enumerate() {
            b[0x18 + i] = *v; // 8 個野手守位
            b[OFF_STATS + i] = 10 + i as u8; // 8 項能力
        }
        b[OFF_DEF] = 71;
        // 球速 154 / 耐力 83 → (154-80) | (83<<7)
        let pack: u16 = (154 - 80) | (83 << 7) | 0xC000;
        b[OFF_PACK] = pack as u8;
        b[OFF_PACK + 1] = (pack >> 8) as u8;
        b[OFF_CATCH] = (7 << CATCH_SHIFT) | 0x80; // 捕手配球 S ＋ 同 byte 的別的旗標
        b[OFF_BATTING_AGGRESSION] = 4 | 0xA0; // 打擊積極性 C ＋ 其他旗標
        b[OFF_BATTING_AGGRESSION_SYNC] = 3 | 0xA0;
        b[OFF_PLATE_DISCIPLINE] = (4 << PLATE_DISCIPLINE_SHIFT) | 0x85; // 選球眼 C ＋ 其他旗標
        b[OFF_PLATE_DISCIPLINE_SYNC] = 0xA0 | 3; // C 的同步值 3 ＋ 高位其他旗標
        b[OFF_GRADE] = 3;
        b[OFF_ITEM] = 1;
        b[OFF_BOOK] = 5;
        b[OFF_TEAM] = 7;
        // 守備位置 SS(5) 放在 +0xA30 的 bit3
        let posw: u16 = (5 << POS_SHIFT) | POPULARITY_ON as u16;
        b[OFF_POS] = posw as u8;
        b[OFF_POS + 1] = (posw >> 8) as u8;
        // 九宮格：第 0 格 +3、第 1 格 −3
        let z: u32 = 3 | (5 << 3);
        b[OFF_ZONE..OFF_ZONE + 4].copy_from_slice(&z.to_le_bytes());
        // 12 個球種 slot：第 0 顆滑球 B/7/C，其餘空
        for k in 0..N_BALL {
            b[OFF_BALL + k * 3] = BALL_EMPTY;
        }
        b[OFF_BALL] = 4;
        b[OFF_BALL + 1] = 5 * 8 + 7;
        b[OFF_BALL + 2] = 4;
        // 姓名（姓 \0 名 \0）
        let nm = b"\xe5\xa4\xa7\xe8\xb0\xb7\x00\xe7\xbf\x94\xe5\xb9\xb3\x00";
        b[OFF_NAME..OFF_NAME + nm.len()].copy_from_slice(nm);
        // 原創球種記錄 0：佔 slot 0
        b[OFF_ORIG..OFF_ORIG + 4].copy_from_slice(&0u32.to_le_bytes());
        b[OFF_ORIG + REC_BASE] = 4;
        b
    }

    #[test]
    fn parse_reads_every_field_from_the_right_offset() {
        let pl = Player::parse(&mkbuf(), 0xDEAD0000).expect("應該解析得出來");
        assert_eq!(pl.addr, 0xDEAD0000);
        assert_eq!(pl.name, "大谷 翔平");
        assert_eq!(pl.stats, [10, 11, 12, 13, 14, 15, 16, 17]);
        assert_eq!(pl.field, [3, 1, 4, 1, 5, 9, 2, 6]);
        assert_eq!(pl.defense, 71);
        assert_eq!(pl.speed, 154);
        assert_eq!(pl.stamina, 83);
        assert_eq!(pl.pack_hi, 0xC000, "bit14-15 的旗標要原樣保留");
        assert_eq!(pl.catcher, 7, "捕手配球只能取 bit4~6，不能被同 byte 的旗標污染");
        assert_eq!(pl.batting_aggression, 4, "打擊積極性 C 應由 +0xA5B low3 解析");
        assert_eq!(pl.plate_discipline, 4, "選球眼 C 應由 +0xA53 bit3~5 解析");
        assert!(pl.popularity, "人氣應由 +0xA30 low3=2 解析");
        assert_eq!(pl.pos, 5);
        assert_eq!(pl.team, 7);
        assert_eq!(pl.grade, 3);
        assert_eq!(pl.item, 1);
        assert_eq!(pl.book, 5);
        assert_eq!(pl.zone[0], 3);
        assert_eq!(pl.zone[1], -3, "九宮格是 3-bit 二補數");
        assert_eq!(pl.balls.len(), N_BALL);
        assert_eq!((pl.balls[0].id, pl.balls[0].power, pl.balls[0].move_), (4, 5, 7));
        assert_eq!(pl.balls[1].id, BALL_EMPTY);
        assert_eq!(pl.recs.len(), N_REC);
        assert_eq!(pl.recs[0].base, 4);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert!(Player::parse(&vec![0u8; PLAYER_READ - 1], 0).is_none());
    }

    #[test]
    fn player_read_covers_every_offset_parse_touches() {
        for (name, off) in [
            ("能力", OFF_STATS + 8),
            ("球種", OFF_BALL + N_BALL * 3),
            ("原創球種記錄", OFF_ORIG + N_REC * REC),
            ("姓名", OFF_NAME + 64),
            ("隊伍", OFF_TEAM + 1),
            ("守備位置", OFF_POS + 2),
            ("打擊積極性", OFF_BATTING_AGGRESSION + 1),
            ("打擊積極性同步", OFF_BATTING_AGGRESSION_SYNC + 1),
            ("選球眼", OFF_PLATE_DISCIPLINE + 1),
            ("選球眼同步", OFF_PLATE_DISCIPLINE_SYNC + 1),
            ("九宮格", OFF_ZONE + 4),
            ("年級", OFF_GRADE + 1),
            ("書籍", OFF_BOOK + 1),
        ] {
            assert!(off <= PLAYER_READ, "{name} 需要讀到 {off:#x}，超過 PLAYER_READ");
        }
    }
}
