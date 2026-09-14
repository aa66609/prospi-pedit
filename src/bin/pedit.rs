//! pedit —— prospi 選手編輯器（原生視窗 GUI）。
//!
//! 左邊選選手、右邊直接拉數值改球種, 不用背 offset 也不用先輸入編號。
//! 栄冠(高中)走指標鏈即時列出部員; 明星選手模式沒有指標鏈, 用全記憶體掃描列出。
//! 所有修改即時寫入記憶體, 遊戲切換畫面後生效。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use prospi::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};

/// 鎖定目標 ＝ 一位選手的一整組「顯示能力值」。
///
/// ⚠ 明星選手模式的能力值有一份**權威來源**（成長／經驗值資料），
/// 我們改的是它算出來的結果。打完比賽或推進日期時遊戲會重新結算並覆寫，
/// 而且會把差值當成「力量已下降 23 了！」報告出來 —— 所以單次寫入撐不到下一場。
/// 對策跟道具一樣：**持續重寫**，遊戲蓋回去就在 0.3 秒內再蓋回來。
#[derive(Clone)]
struct LockTarget {
    addr: usize,
    /// 寫入前拿來比對，防止物件搬家後寫進別人的資料
    name: String,
    stats: [u8; 8],
    defense: u8,
    speed: u16,
    stamina: u16,
    pack_hi: u16,
    abil: [u8; ABIL_BYTES],
    /// 12 slot × 3 bytes，已編碼成記憶體的樣子
    balls: Vec<u8>,
}

impl LockTarget {
    fn of(pl: &Player) -> LockTarget {
        LockTarget {
            addr: pl.addr,
            name: pl.name.clone(),
            stats: pl.stats,
            defense: pl.defense,
            speed: pl.speed,
            stamina: pl.stamina,
            pack_hi: pl.pack_hi,
            abil: pl.abil,
            balls: pl
                .balls
                .iter()
                .flat_map(|b| [b.id, b.power * 8 + b.move_, b.control])
                .collect(),
        }
    }
}

/// 常規作弊開關。全部走「背景執行緒每 0.3 秒重寫一次」，
/// 因為這些值遊戲會自己扣（道具消耗、使用次數累加），單次寫入撐不住。
/// 這也免掉了 hook 程式碼 —— 效果等同 CT 那幾個 AA 腳本，但不必動到 exe。
#[derive(Default)]
struct Cheats {
    koshien_items: AtomicBool,
    koshien_limit: AtomicBool,
    koshien_prac: AtomicBool,
    shared_items: AtomicBool,
    star_items: AtomicBool,
    /// 鎖定選中的選手（對抗明星選手模式的成長結算回寫）
    lock_player: AtomicBool,
    /// 連球種一起鎖（預設關 —— 否則在遊戲內學到的新球種也會被蓋掉）
    lock_balls: AtomicBool,
    /// 鎖定目標。None ＝ 還沒指定
    lock: Mutex<Option<LockTarget>>,
    /// 上一輪姓名比對失敗 ＝ 物件搬家了（讀過存檔／遊戲重開），UI 要提示重新掃描
    lock_stale: AtomicBool,
    /// 心跳：套用過幾輪，讓 UI 能顯示「有在跑」
    ticks: AtomicUsize,
}

impl Cheats {
    fn any_on(&self) -> bool {
        [&self.koshien_items, &self.koshien_limit, &self.koshien_prac,
         &self.shared_items, &self.star_items, &self.lock_player]
            .iter()
            .any(|f| f.load(Ordering::Relaxed))
    }
}

/// 背景套用執行緒。自己持有 Proc 並在遊戲重開後重新附加，
/// 不跟 UI 那條共用 —— 否則使用者按「重新附加」時會打架。
fn spawn_cheat_worker(c: Arc<Cheats>) {
    std::thread::spawn(move || {
        let mut proc: Option<Proc> = None;
        loop {
            if c.any_on() {
                let alive = proc.as_ref().is_some_and(|p: &Proc| {
                    matches!(p.read(p.base, 2), Some(b) if b == [0x4D, 0x5A])
                });
                if !alive {
                    proc = Proc::attach().ok();
                }
                if let Some(p) = &proc {
                    // 不在對應模式時這些會靜靜失敗（指標鏈是 0），不必特別處理
                    if c.koshien_items.load(Ordering::Relaxed) {
                        set_koshien_items(p, 99);
                    }
                    if c.koshien_limit.load(Ordering::Relaxed) {
                        clear_koshien_use_limits(p);
                    }
                    // 平時一天才減 1，但**觸發經理事件時遊戲會把它夾回 99**，
                    // 所以還是得持續蓋回去
                    if c.koshien_prac.load(Ordering::Relaxed) {
                        set_koshien_pracbuff(p, KOSHIEN_PRACBUFF_DAYS);
                    }
                    if c.shared_items.load(Ordering::Relaxed) {
                        set_shared_items(p, 99);
                    }
                    if c.star_items.load(Ordering::Relaxed) {
                        clear_star_item_uses(p);
                    }
                    if c.lock_player.load(Ordering::Relaxed) {
                        apply_lock(p, &c);
                    }
                    c.ticks.fetch_add(1, Ordering::Relaxed);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    });
}

/// 把鎖定目標的數值寫回去。
///
/// ⚠ **每次寫入前都要比對姓名** —— 明星選手模式讀取存檔後物件會整批搬家，
/// 平移量還不固定，拿舊位址硬寫會寫進別人的資料（`sane_name` 那段註解記的就是這個坑）。
fn apply_lock(p: &Proc, c: &Cheats) {
    let t = match c.lock.lock() {
        Ok(g) => match g.as_ref() {
            Some(t) => t.clone(),
            None => return,
        },
        Err(_) => return,
    };
    let live = read_name(p, t.addr);
    if live != t.name || !sane_name(&live) {
        c.lock_stale.store(true, Ordering::Relaxed);
        return;
    }
    write_pack(p, t.addr, t.speed, t.stamina, t.pack_hi);
    p.write(t.addr + OFF_STATS, &t.stats);
    p.write(t.addr + OFF_DEF, &[t.defense]);
    p.write(t.addr + OFF_ABIL2, &t.abil);
    if c.lock_balls.load(Ordering::Relaxed) {
        p.write(t.addr + OFF_BALL, &t.balls);
    }
    c.lock_stale.store(false, Ordering::Relaxed);
}

fn cheat_box(ui: &mut egui::Ui, flag: &AtomicBool, text: &str, hint: &str) {
    let mut v = flag.load(Ordering::Relaxed);
    if ui.checkbox(&mut v, text).on_hover_text(hint).changed() {
        flag.store(v, Ordering::Relaxed);
    }
}

const FONT_CANDIDATES: &[&str] = &[
    "C:/Windows/Fonts/msjh.ttc",
    "C:/Windows/Fonts/msyh.ttc",
    "C:/Windows/Fonts/meiryo.ttc",
    "C:/Windows/Fonts/mingliu.ttc",
    "C:/Windows/Fonts/simsun.ttc",
    "C:/Windows/Fonts/YuGothM.ttc",
    "C:/Windows/Fonts/kaiu.ttf",
];

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let mut added = Vec::new();
    for (i, path) in FONT_CANDIDATES.iter().enumerate() {
        if let Ok(bytes) = std::fs::read(path) {
            let key = format!("cjk{i}");
            fonts.font_data.insert(key.clone(), egui::FontData::from_owned(bytes));
            added.push(key);
        }
    }
    if added.is_empty() {
        return; // 沒有 CJK 字型就用預設（中文會變豆腐, 但不至於當掉）
    }
    for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        let list = fonts.families.entry(fam).or_default();
        for (n, key) in added.iter().enumerate() {
            list.insert(n, key.clone());
        }
    }
    ctx.set_fonts(fonts);
}

enum ScanMsg {
    Progress(usize, usize),
    Done(Vec<Player>),
    Failed(String),
}

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Koshien,
    /// 明星選手：全記憶體掃描列出所有選手（約 100 秒）
    Scan,
    /// 明星選手：**只找主角**。用門檻表 AOB 先掃熱區（0xd0000000~0xf0000000），
    /// 命中 −0xB014 ＝ 主角物件。約 5 秒，不必等全掃。
    Star,
}

/// 栄冠左側名單的顯示方式。
/// Sorted ＝ 既有的守備位置／能力排序；Raw ＝ roster array 原始 index 順序。
#[derive(PartialEq, Clone, Copy)]
enum KoshienRosterView {
    Sorted,
    Raw,
    Recruit,
}

#[derive(Clone)]
struct RecruitEntry {
    index: usize,
    candidate_addr: usize,
    player: Player,
}

/// 能力研究用的選手物件記憶體快照。
#[derive(Clone)]
struct ResearchSnapshot {
    addr: usize,
    name: String,
    data: Vec<u8>,
}

#[derive(Clone, Copy)]
struct ResearchDiff {
    off: usize,
    before: u8,
    after: u8,
    xor: u8,
}


struct App {
    proc: Option<Proc>,
    err: String,
    mode: Mode,
    koshien_roster_view: KoshienRosterView,
    /// 新生招募：目前選擇的地區 index。
    recruit_region: usize,
    /// 新生招募：目前真正有候選名單的地區。
    recruit_regions: Vec<usize>,
    /// 新生天才出現機率（0..=100）。原生預設 1%。
    talent_rate: u8,
    /// 招募成功率 100% patch 的 UI 狀態。
    recruit_rate_100: bool,
    /// 上一次已讀取的 Region；即使結果是空的也不會每幀重掃。
    recruit_loaded_region: Option<usize>,
    /// 新生招募：目前地區的候選人（保留原始 candidate index 0..9）。
    recruit_list: Vec<RecruitEntry>,
    recruit_sel: Option<usize>,
    recruit_cur: Option<Player>,
    /// 新生招募分頁開啟時，每 2 秒檢查候選人並同步能力/總評。
    last_recruit_refresh: std::time::Instant,
    /// 榮冠 roster 尚未出現時，每 1 秒重試一次。
    last_koshien_retry: std::time::Instant,
    /// roster 已取得後，每 5 秒做一次輕量有效性檢查。
    last_koshien_validate: std::time::Instant,
    /// 已知球員物件每 2 秒重新讀一次能力，讓清單總評跟遊戲內成長同步。
    /// 這不是全記憶體掃描，只讀 self.list 已知的 Player Object。
    last_koshien_stat_sync: std::time::Instant,
    filter: String,
    list: Vec<Player>,
    sel: Option<usize>,
    cur: Option<Player>,
    lib: Vec<LibEntry>,
    /// `origlib.json` 的位置 —— 「蒐集到球種庫」要寫回這裡
    libpath: std::path::PathBuf,
    /// 隊伍 ID → 隊名（記憶體裡查不到，使用者自己填，存 `teams.json`）
    teams: std::collections::HashMap<u8, String>,
    rename_team: Option<u8>,
    /// 合併同名副本（同隊同名只留一份）
    merge_dups: bool,
    /// (隊伍, 姓名) → (代表的 index, 總份數)。在 reload 時算一次 ——
    /// ⚠ 這裡面要讀記憶體判斷成長經驗值結構，**絕對不能放進每幀路徑**
    dup_rep: std::collections::HashMap<(u8, String), (usize, usize)>,
    /// 帶成長經驗值結構的物件 ＝ 明星選手的主角。清單上標 ★，代表選這份才對。
    growth_owners: std::collections::HashSet<usize>,
    rename_buf: String,
    scan_rx: Option<Receiver<ScanMsg>>,
    scan_prog: (usize, usize),
    status: String,
    cross_dir: bool,
    only_pitchers: bool,
    /// 成長經驗值要練到幾（0..99）。不是無腦灌滿, 可以指定
    growth_target: i32,
    /// 目前選中選手的成長經驗值結構（在 reload_current 時算好, 不要每幀重算）
    growth_base: Option<usize>,
    /// 能力研究：修改前快照。只存在修改器 RAM，不會寫回遊戲。
    research_before: Option<ResearchSnapshot>,
    /// 能力研究：最近一次比較結果。
    research_diffs: Vec<ResearchDiff>,
    /// 快照讀取長度。0x2000 比目前已知 PLAYER_READ(0x1520) 多留一些空間，
    /// 仍可在 UI 改成已知範圍或更大的研究範圍。
    research_len: usize,
    /// 差分顯示時只看「恰好一個 bit 改變」的 byte，能快速排除大量計數器/數值變化。
    research_single_bit_only: bool,
    /// 任意 offset 研究工具：相對於目前選手物件的 offset（十六進位文字）。
    research_offset_text: String,
    /// 任意 offset 研究工具：準備寫入的單一 byte（十六進位文字）。
    research_value_text: String,
    /// 最近一次載入：(選手物件位址, offset, 原始值)。切換選手後不允許沿用。
    research_loaded_byte: Option<(usize, usize, u8)>,
    cheats: Arc<Cheats>,
}

const RECRUIT_REGION_NAMES: [&str; 49] = [
    "北北海道", "南北海道", "青森", "岩手", "秋田", "山形", "宮城", "福島",
    "茨城", "栃木", "群馬", "埼玉", "千葉", "神奈川", "山梨", "東東京", "西東京",
    "新潟", "長野", "富山", "石川", "福井", "静岡", "愛知", "岐阜", "三重", "滋賀",
    "京都", "大阪", "兵庫", "奈良", "和歌山", "岡山", "廣島", "鳥取", "島根", "山口",
    "香川", "徳島", "愛媛", "高知", "福岡", "佐賀", "長崎", "熊本", "大分", "宮崎",
    "鹿児島", "沖縄",
];

fn recruit_region_label(index: usize) -> String {
    RECRUIT_REGION_NAMES
        .get(index)
        .map(|name| format!("{index}. {name}"))
        .unwrap_or_else(|| format!("{index}"))
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);
        let libpath = origlib_path();
        // 啟動時只附加遊戲，不主動檢查或改寫招募機率的程式碼。
        // 招募機率 patch 的生命週期只由本次修改器 instance 的 checkbox 管理。
        let (proc, err) = match Proc::attach() {
            Ok(p) => (Some(p), String::new()),
            Err(e) => (None, e),
        };
        let initial_talent_rate = proc.as_ref().and_then(talent_rate).unwrap_or(TALENT_RATE_DEFAULT);
        let mut app = App {
            proc,
            err,
            mode: Mode::Koshien,
            koshien_roster_view: KoshienRosterView::Sorted,
            recruit_region: 0,
            recruit_regions: Vec::new(),
            talent_rate: initial_talent_rate,
            recruit_rate_100: false,
            recruit_loaded_region: None,
            recruit_list: Vec::new(),
            recruit_sel: None,
            recruit_cur: None,
            last_recruit_refresh: std::time::Instant::now(),
            last_koshien_retry: std::time::Instant::now(),
            last_koshien_validate: std::time::Instant::now(),
            last_koshien_stat_sync: std::time::Instant::now(),
            filter: String::new(),
            list: Vec::new(),
            sel: None,
            cur: None,
            lib: load_lib(&libpath),
            libpath,
            teams: load_teams(&teams_path()),
            rename_team: None,
            merge_dups: true,
            dup_rep: std::collections::HashMap::new(),
            growth_owners: std::collections::HashSet::new(),
            rename_buf: String::new(),
            scan_rx: None,
            scan_prog: (0, 0),
            status: String::new(),
            cross_dir: false,
            only_pitchers: false,
            growth_target: 99,
            growth_base: None,
            research_before: None,
            research_diffs: Vec::new(),
            research_len: 0x2000,
            research_single_bit_only: true,
            research_offset_text: "0x002D".into(),
            research_value_text: String::new(),
            research_loaded_byte: None,
            cheats: Arc::new(Cheats::default()),
        };
        spawn_cheat_worker(app.cheats.clone());
        app.reload_list();
        app
    }

    /// 現有 handle 是否還指向活著的遊戲行程。
    /// 遊戲重開後 pid 會變，舊 handle 讀什麼都回 None —— 讀模組基址的 `MZ` 就能判斷。
    fn proc_alive(&self) -> bool {
        match &self.proc {
            Some(p) => matches!(p.read(p.base, 2), Some(b) if b == [0x4D, 0x5A]),
            None => false,
        }
    }

    /// 附加失效就自動重新附加。**每次重新整理／切模式前都要跑**，
    /// 否則使用者關掉遊戲重讀存檔後會一直看到「讀不到部員名單」而不知道是 pid 變了。
    fn ensure_proc(&mut self) -> bool {
        if self.proc_alive() {
            return true;
        }
        // 如果這次修改器自己曾套用招募機率資料表 patch，先嘗試還原。
        // 若遊戲 process 已經真的消失，寫回會失敗也沒關係：process 結束後資料 patch 本身也不存在。
        if self.recruit_rate_100 {
            if let Some(p) = self.proc.as_ref() {
                let _ = set_recruit_rate_100(p, false);
            }
            self.recruit_rate_100 = false;
        }
        let old = self.proc.take().map(|p| p.pid);
        self.recruit_loaded_region = None;
        self.recruit_list.clear();
        self.recruit_sel = None;
        self.recruit_cur = None;
        match Proc::attach() {
            Ok(p) => {
                let attach_msg = match old {
                    Some(o) => format!("遊戲已重開（pid {o} → {}），已自動重新附加", p.pid),
                    None => format!("已附加 pid {}", p.pid),
                };
                self.status = attach_msg;
                self.recruit_rate_100 = false;
                self.talent_rate = talent_rate(&p).unwrap_or(TALENT_RATE_DEFAULT);
                self.proc = Some(p);
                self.err.clear();
                true
            }
            Err(e) => {
                self.err = e;
                self.sel = None;
                self.cur = None;
                self.list.clear();
                false
            }
        }
    }

    /// 榮冠新版 roster 的 +0x20 child pointer 會隨遊戲畫面狀態切換。
    /// 因此修改器若比球員名單更早啟動，第一次讀不到 roster 是正常狀況。
    ///
    /// - 尚未取得名單：每 1 秒重試，成功後停止高頻重試。
    /// - 已取得名單：每 5 秒確認 roster pointer / 姓名仍有效。
    /// - 遊戲重開或 Player Object 搬家：自動重新附加／重新載入。
    fn auto_refresh_koshien(&mut self, ctx: &egui::Context) {
        if self.mode != Mode::Koshien {
            return;
        }

        let now = std::time::Instant::now();

        if self.list.is_empty() {
            if now.duration_since(self.last_koshien_retry) >= std::time::Duration::from_secs(1) {
                self.last_koshien_retry = now;
                self.reload_list();
                if !self.list.is_empty() {
                    self.status = format!("已自動取得榮冠部員名單（{} 人）", self.list.len());
                }
            }
            // 即使視窗沒有輸入事件，也要讓下一次自動重試能準時執行。
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
            return;
        }

        // 已取得 roster 後，每 2 秒只重讀「已知 Player Object」的最新內容。
        // 不掃描記憶體、不重建 roster，也不碰 growth structure；用途只是讓
        // 遊戲內自然成長/能力變動後，清單上的 overall 最多約 2 秒就同步。
        if now.duration_since(self.last_koshien_stat_sync) >= std::time::Duration::from_secs(2) {
            self.last_koshien_stat_sync = now;
            if let Some(p) = self.proc.as_ref() {
                let selected = self.sel;
                let mut selected_fresh: Option<Player> = None;
                for (i, pl) in self.list.iter_mut().enumerate() {
                    let addr = pl.addr;
                    if let Some(fresh) = Player::load(p, addr) {
                        // 位址與姓名都合理才覆蓋快照，避免畫面切換瞬間讀到別的物件。
                        if fresh.addr == addr && fresh.name == pl.name {
                            if selected == Some(i) {
                                selected_fresh = Some(fresh.clone());
                            }
                            *pl = fresh;
                        }
                    }
                }
                // 選中的球員也要一起刷新右側編輯快照，避免舊 cur 與新 list 打架。
                if let Some(fresh) = selected_fresh {
                    self.cur = Some(fresh);
                }
            }
        }

        if now.duration_since(self.last_koshien_validate) < std::time::Duration::from_secs(5) {
            ctx.request_repaint_after(std::time::Duration::from_secs(2));
            return;
        }
        self.last_koshien_validate = now;

        // 遊戲真正重開：舊 handle 已失效，直接走 reload_list()，其中 ensure_proc() 會重新附加。
        if !self.proc_alive() {
            self.reload_list();
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
            return;
        }

        let needs_reload = match &self.proc {
            Some(p) => {
                let objs = koshien_roster(p);
                if objs.is_empty() {
                    // 可能只是暫時離開 roster 有效畫面。保留現有清單，不要讓 UI 閃成空白。
                    false
                } else {
                    let pointers_changed = objs.len() != self.list.len()
                        || objs.iter().zip(self.list.iter()).any(|(&a, pl)| a != pl.addr);
                    let first_name_changed = objs.first().is_some_and(|&a| {
                        let live = read_name(p, a);
                        self.list.first().is_some_and(|pl| live != pl.name || !sane_name(&live))
                    });
                    pointers_changed || first_name_changed
                }
            }
            None => true,
        };

        if needs_reload {
            self.reload_list();
            if !self.list.is_empty() {
                self.status = format!("偵測到榮冠名單更新，已自動重新載入（{} 人）", self.list.len());
            }
        }

        ctx.request_repaint_after(std::time::Duration::from_secs(2));
    }

    /// 新生招募分頁自動刷新：每 2 秒檢查 Candidate 是否換人，並同步目前候選人的能力/總評。
    /// 只有 Candidate index / pointer / 姓名改變時才重建清單；平常只重讀這 10 位已知 Player Object。
    fn auto_refresh_recruit_regions(&mut self, ctx: &egui::Context) {
        if self.mode != Mode::Koshien || self.koshien_roster_view != KoshienRosterView::Recruit {
            return;
        }

        let now = std::time::Instant::now();
        if now.duration_since(self.last_recruit_refresh) < std::time::Duration::from_secs(2) {
            ctx.request_repaint_after(std::time::Duration::from_secs(2));
            return;
        }
        self.last_recruit_refresh = now;

        // Region / Candidate 只有在榮冠 roster 已就緒時才讀取。
        // 注意：這個門檻只限制招募資料，不影響上方兩個 exe runtime patch。
        let regions = match self.proc.as_ref() {
            Some(p) if !koshien_roster(p).is_empty() => recruit_available_regions(p),
            _ => Vec::new(),
        };

        // 離開榮冠或 roster 尚未就緒時，立即清掉先前的 Region / Candidate 顯示。
        if regions.is_empty() {
            self.recruit_regions.clear();
            self.recruit_list.clear();
            self.recruit_sel = None;
            self.recruit_cur = None;
            self.recruit_loaded_region = None;
            ctx.request_repaint_after(std::time::Duration::from_secs(2));
            return;
        }

        if regions != self.recruit_regions {
            // 地區清單本身發生變化，就重新載入目前 Region 的候選人。
            self.recruit_regions = regions;
            if !self.recruit_regions.contains(&self.recruit_region) {
                if let Some(&r) = self.recruit_regions.first() {
                    self.recruit_region = r;
                }
            }
            self.reload_recruits();
        } else {
            // Region 沒變時先確認 Candidate 本身是否換人。
            let candidate_changed = match self.proc.as_ref() {
                Some(p) => {
                    let live = recruit_candidates(p, self.recruit_region);
                    live.len() != self.recruit_list.len()
                        || live.iter().zip(self.recruit_list.iter()).any(|(&(index, candidate_addr, obj), old)| {
                            index != old.index
                                || candidate_addr != old.candidate_addr
                                || obj != old.player.addr
                                || read_name(p, obj) != old.player.name
                        })
                }
                None => false,
            };

            if candidate_changed {
                self.reload_recruits();
            } else if let Some(p) = self.proc.as_ref() {
                // Candidate 沒換人：每 2 秒重讀已知 Player Object，更新能力與 overall。
                // 若目前正選中某位候選人，右側 recruit_cur 也一起刷新，避免新舊快照互相覆蓋。
                let selected = self.recruit_sel;
                let mut selected_fresh: Option<Player> = None;
                for (i, e) in self.recruit_list.iter_mut().enumerate() {
                    let addr = e.player.addr;
                    if let Some(fresh) = Player::load(p, addr) {
                        if fresh.addr == addr && fresh.name == e.player.name {
                            if selected == Some(i) {
                                selected_fresh = Some(fresh.clone());
                            }
                            e.player = fresh;
                        }
                    }
                }
                if let Some(fresh) = selected_fresh {
                    self.recruit_cur = Some(fresh);
                }
            }
        }

        ctx.request_repaint_after(std::time::Duration::from_secs(2));
    }

    fn reload_recruits(&mut self) {
        // 不在榮冠（或 roster 尚未就緒）時，絕不碰 Region / Candidate。
        // 天才機率與招募機率 100% 是 exe patch，刻意不受此條件限制。
        let roster_ready = self.proc.as_ref()
            .is_some_and(|p| !koshien_roster(p).is_empty());
        if !roster_ready {
            self.recruit_regions.clear();
            self.recruit_list.clear();
            self.recruit_sel = None;
            self.recruit_cur = None;
            self.recruit_loaded_region = Some(self.recruit_region);
            self.status = "讀不到部員名單 —— 現在不在栄冠(高中)模式? 新生招募地區尚未啟動".into();
            return;
        }

        if let Some(p) = self.proc.as_ref() {
            self.recruit_regions = recruit_available_regions(p);
            if !self.recruit_regions.contains(&self.recruit_region) {
                if let Some(&r) = self.recruit_regions.first() { self.recruit_region = r; }
            }
        }
        self.recruit_loaded_region = Some(self.recruit_region);
        self.recruit_list.clear();
        self.recruit_sel = None;
        self.recruit_cur = None;
        let p = match &self.proc {
            Some(p) => p,
            None => return,
        };
        for (index, candidate_addr, obj) in recruit_candidates(p, self.recruit_region) {
            if let Some(player) = Player::load(p, obj) {
                self.recruit_list.push(RecruitEntry { index, candidate_addr, player });
            }
        }
        self.status = if self.recruit_list.is_empty() {
            format!("新生招募：Region {} 目前讀不到候選球員", self.recruit_region)
        } else {
            format!("新生招募：Region {} 讀到 {} 位候選球員", self.recruit_region, self.recruit_list.len())
        };
    }

    fn reload_list(&mut self) {
        if !self.ensure_proc() {
            return;
        }
        let p = match &self.proc {
            Some(p) => p,
            None => return,
        };
        match self.mode {
            Mode::Koshien => {
                let objs = koshien_roster(p);
                if objs.is_empty() {
                    self.status =
                        "讀不到部員名單 —— 現在不在栄冠(高中)模式? 可改用「明星選手(掃描)」".into();
                }
                self.list = objs.iter().filter_map(|&o| Player::load(p, o)).collect();
                self.sel = None;
                self.cur = None;
            }
            Mode::Scan => self.start_scan(false),
            Mode::Star => self.start_scan(true),
        }
        self.rebuild_dups();
    }

    /// 算出每位選手（同隊同名）要用哪一份當代表。**只在 reload 時跑一次。**
    ///
    /// 挑選順序：
    /// 1. **有成長經驗值結構（`+0xB014`）的那份** —— 明星選手的主角是這樣，
    ///    他的能力值由經驗值算出來，副本會留著舊值。這是結構性判別，最可靠。
    /// 2. 否則取**位址最小**的那份（12 位對照畫面值中 11 位正確的經驗法則）。
    fn rebuild_dups(&mut self) {
        self.dup_rep.clear();
        self.growth_owners.clear();
        let mut group: std::collections::HashMap<(u8, String), Vec<usize>> =
            std::collections::HashMap::new();
        for (i, pl) in self.list.iter().enumerate() {
            group.entry((pl.team, pl.name.clone())).or_default().push(i);
        }
        for (k, mut idxs) in group {
            idxs.sort_by_key(|&i| self.list[i].addr);
            let mut rep = idxs[0];
            if idxs.len() > 1 {
                if let Some(p) = &self.proc {
                    // 只對「真的有多份」的選手做記憶體判斷，數量很少
                    for &i in &idxs {
                        if growth_struct_for(p, self.list[i].addr).is_some() {
                            self.growth_owners.insert(i);
                        }
                    }
                    if let Some(&g) = idxs.iter().find(|i| self.growth_owners.contains(i)) {
                        rep = g;
                    }
                }
            }
            self.dup_rep.insert(k, (rep, idxs.len()));
        }
    }

    fn start_scan(&mut self, fast: bool) {
        if self.scan_rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        self.scan_rx = Some(rx);
        self.scan_prog = (0, 1);
        self.status = if fast { "找主角中（約 5 秒）…" } else { "掃描中（約 100 秒）…" }.into();
        std::thread::spawn(move || match Proc::attach() {
            Ok(p) => {
                if fast {
                    // 主角 ＝ 經驗值結構 − 0xB014。順便去重（同一位主角有多份結構）
                    let mut v: Vec<Player> = find_growth_structs_fast(&p)
                        .into_iter()
                        .filter_map(|g| Player::load(&p, g.checked_sub(GROWTH_FROM_PLAYER)?))
                        .filter(|pl| sane_name(&pl.name))
                        .collect();
                    v.dedup_by(|a, b| a.name == b.name && a.stats == b.stats && a.speed == b.speed);
                    let _ = tx.send(ScanMsg::Done(v));
                    return;
                }
                let tx2 = tx.clone();
                let players = scan_players(&p, move |d, t| {
                    let _ = tx2.send(ScanMsg::Progress(d, t));
                });
                let _ = tx.send(ScanMsg::Done(players));
            }
            Err(e) => {
                let _ = tx.send(ScanMsg::Failed(e));
            }
        });
    }

    fn poll_scan(&mut self, ctx: &egui::Context) {
        let mut done = false;
        if let Some(rx) = &self.scan_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanMsg::Progress(d, t) => {
                        self.scan_prog = (d, t.max(1));
                        ctx.request_repaint();
                    }
                    ScanMsg::Done(v) => {
                        self.status = format!("掃描完成，找到 {} 位選手", v.len());
                        self.list = v;
                        self.sel = None;
                        self.cur = None;
                        done = true;
                    }
                    ScanMsg::Failed(e) => {
                        self.status = e;
                        done = true;
                    }
                }
            }
        }
        if done {
            self.scan_rx = None;
            // 掃描是背景執行緒, 結果晚到 —— 這裡才是名單真正就緒的時候
            self.rebuild_dups();
        }
    }

    fn reload_current(&mut self) {
        let i = match self.sel {
            Some(i) => i,
            None => return,
        };
        let addr = match self.list.get(i) {
            Some(pl) => pl.addr,
            None => return,
        };

        // 重新讀取時不只更新右側編輯器的 cur，也同步更新左側清單的快照。
        // player_row() 的總評是由 self.list[i].overall() 計算；若只更新 cur，
        // 左側就會一直顯示選手剛載入時的舊總評。
        let loaded = self.proc.as_ref().and_then(|p| Player::load(p, addr));
        self.growth_base = self.proc.as_ref().and_then(|p| growth_struct_for(p, addr));
        if let Some(pl) = loaded {
            self.cur = Some(pl.clone());
            if let Some(slot) = self.list.get_mut(i) {
                if slot.addr == addr {
                    *slot = pl;
                }
            }
        }
    }

    /// 把目前載入的選手身上的原創球種記錄併進球種庫並存檔。
    ///
    /// 發布的 `origlib.json` 只附官方球種（人人都有），自訂球種是各人存檔獨有的，
    /// 靠這個從自己的遊戲裡補進來。
    fn collect_lib(&mut self) {
        let mut n = merge_recs_into_lib(&mut self.lib, &self.list);
        if let Some(c) = self.cur.clone() {
            n += merge_recs_into_lib(&mut self.lib, std::slice::from_ref(&c));
        }
        let dst = origlib_save_path();
        // 非全掃模式的清單只有少數選手，蒐集不完 —— 收完再提醒一次
        let more = if self.mode == Mode::Scan {
            String::new()
        } else {
            "　※ 切到「明星選手(全掃)」再按一次可以蒐集到更多".into()
        };
        self.status = match save_lib(&dst, &self.lib) {
            Ok(()) if n == 0 => format!(
                "球種庫沒有新增（這些球種都已經在庫裡了）—— 目前共 {} 筆{more}",
                self.lib.len()
            ),
            Ok(()) => format!(
                "✓ 球種庫新增 {n} 筆，目前共 {} 筆 → {}{more}",
                self.lib.len(),
                dst.display()
            ),
            Err(e) => e,
        };
    }

    /// 能力研究：對目前選中的選手記錄修改前快照。
    fn research_capture_before(&mut self) {
        let (obj, name) = match self.cur.as_ref() {
            Some(pl) => (pl.addr, pl.name.clone()),
            None => {
                self.status = "請先選一位選手".into();
                return;
            }
        };
        let p = match self.proc.as_ref() {
            Some(p) => p,
            None => {
                self.status = "尚未附加遊戲行程".into();
                return;
            }
        };
        let live = read_name(p, obj);
        if live != name || !sane_name(&live) {
            self.status = "記錄失敗：選手位址已失效，請先重新整理".into();
            return;
        }
        match p.read(obj, self.research_len) {
            Some(data) if !data.is_empty() => {
                let got = data.len();
                self.research_before = Some(ResearchSnapshot {
                    addr: obj,
                    name: name.clone(),
                    data,
                });
                self.research_diffs.clear();
                self.status = format!(
                    "能力研究：已記錄「{name}」修改前快照 {got:#x} bytes（物件 {obj:#x}）"
                );
            }
            _ => self.status = "能力研究：讀取修改前快照失敗".into(),
        }
    }

    /// 能力研究：讀取目前記憶體並與修改前快照比較。
    fn research_compare_after(&mut self) {
        let before = match self.research_before.clone() {
            Some(v) => v,
            None => {
                self.status = "請先按「① 記錄修改前」".into();
                return;
            }
        };
        let (obj, name) = match self.cur.as_ref() {
            Some(pl) => (pl.addr, pl.name.clone()),
            None => {
                self.status = "請先選一位選手".into();
                return;
            }
        };
        if obj != before.addr || name != before.name {
            self.status = format!(
                "能力研究：目前選中的是「{name}」({obj:#x})，不是快照中的「{}」({:#x})；請重新記錄修改前",
                before.name, before.addr
            );
            return;
        }
        let p = match self.proc.as_ref() {
            Some(p) => p,
            None => {
                self.status = "尚未附加遊戲行程".into();
                return;
            }
        };
        let live = read_name(p, obj);
        if live != name || !sane_name(&live) {
            self.status = "比較失敗：選手位址已失效；請重新整理後重新做一輪實驗".into();
            return;
        }
        let after = match p.read(obj, before.data.len()) {
            Some(v) if !v.is_empty() => v,
            _ => {
                self.status = "能力研究：讀取修改後快照失敗".into();
                return;
            }
        };
        let n = before.data.len().min(after.len());
        self.research_diffs.clear();
        self.research_diffs.reserve(64);
        for i in 0..n {
            let a = before.data[i];
            let b = after[i];
            if a != b {
                self.research_diffs.push(ResearchDiff {
                    off: i,
                    before: a,
                    after: b,
                    xor: a ^ b,
                });
            }
        }
        self.status = format!(
            "能力研究：比較完成，共 {} 個 byte 有變化（掃描 {n:#x} bytes）",
            self.research_diffs.len()
        );
    }

    /// 把修改前快照與差分文字輸出到 exe 同層，方便保存實驗或傳給別人分析。
    fn research_export(&mut self) {
        let before = match self.research_before.as_ref() {
            Some(v) => v,
            None => {
                self.status = "沒有可匯出的能力研究快照".into();
                return;
            }
        };
        let dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let base = format!("research_{stamp}");
        let bin = dir.join(format!("{base}_before.bin"));
        let txt = dir.join(format!("{base}_diff.txt"));
        let mut report = String::new();
        report.push_str(&format!(
            "player={}\naddr={:#x}\nbytes={:#x}\ndiff_count={}\n\n",
            before.name,
            before.addr,
            before.data.len(),
            self.research_diffs.len()
        ));
        for d in &self.research_diffs {
            let bit = if d.xor.count_ones() == 1 {
                format!("bit{}", d.xor.trailing_zeros())
            } else {
                format!("{} bits", d.xor.count_ones())
            };
            report.push_str(&format!(
                "+0x{:04X}  {:02X} -> {:02X}  XOR={:02X}  {}\n",
                d.off, d.before, d.after, d.xor, bit
            ));
        }
        let ok_bin = std::fs::write(&bin, &before.data);
        let ok_txt = std::fs::write(&txt, report);
        self.status = if ok_bin.is_ok() && ok_txt.is_ok() {
            format!("能力研究已匯出：{}、{}", bin.display(), txt.display())
        } else {
            format!("能力研究匯出失敗：{}", dir.display())
        };
    }

    /// 研究工具的十六進位輸入。接受 `0x002D`、`+0x002D`、`002D`。
    fn parse_research_hex(text: &str) -> Option<usize> {
        let t = text.trim();
        let t = t.strip_prefix('+').unwrap_or(t);
        let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
        if t.is_empty() || !t.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        usize::from_str_radix(t, 16).ok()
    }

    /// 從目前選手物件載入任意 offset 的單一 byte。
    fn research_load_byte(&mut self) {
        let off = match Self::parse_research_hex(&self.research_offset_text) {
            Some(v) if v <= 0xFFFF => v,
            _ => {
                self.status = "Offset 格式錯誤：請輸入例如 0x002D（範圍 0x0000..0xFFFF）".into();
                return;
            }
        };
        let (obj, name) = match self.cur.as_ref() {
            Some(pl) => (pl.addr, pl.name.clone()),
            None => {
                self.status = "請先選一位選手".into();
                return;
            }
        };
        let p = match self.proc.as_ref() {
            Some(p) => p,
            None => {
                self.status = "尚未附加遊戲行程".into();
                return;
            }
        };
        let live = read_name(p, obj);
        if live != name || !sane_name(&live) {
            self.status = "載入失敗：選手位址已失效，請先重新整理".into();
            return;
        }
        match p.read(obj + off, 1).and_then(|b| b.first().copied()) {
            Some(v) => {
                self.research_loaded_byte = Some((obj, off, v));
                self.research_value_text = format!("{v:02X}");
                self.status = format!(
                    "任意 Offset：已載入「{name}」+0x{off:04X} = 0x{v:02X}"
                );
            }
            None => self.status = format!("任意 Offset：讀取 +0x{off:04X} 失敗"),
        }
    }

    /// 把研究工具輸入的單一 byte 寫回目前選手物件。
    fn research_write_byte(&mut self) {
        let (obj, off, old) = match self.research_loaded_byte {
            Some(v) => v,
            None => {
                self.status = "請先按「載入」確認目前 offset 與原始值".into();
                return;
            }
        };
        let (cur_obj, name) = match self.cur.as_ref() {
            Some(pl) => (pl.addr, pl.name.clone()),
            None => {
                self.status = "請先選一位選手".into();
                return;
            }
        };
        if cur_obj != obj {
            self.status = "目前選手已切換；請重新按「載入」後再寫入".into();
            self.research_loaded_byte = None;
            return;
        }
        // 使用者若改了 offset 輸入框，必須重新載入，避免畫面顯示 A offset 卻寫到舊的 B offset。
        if Self::parse_research_hex(&self.research_offset_text) != Some(off) {
            self.status = "Offset 已變更；請重新按「載入」再寫入".into();
            return;
        }
        let nv = match Self::parse_research_hex(&self.research_value_text) {
            Some(v) if v <= 0xFF => v as u8,
            _ => {
                self.status = "數值格式錯誤：請輸入 00..FF（十六進位）".into();
                return;
            }
        };
        let p = match self.proc.as_ref() {
            Some(p) => p,
            None => {
                self.status = "尚未附加遊戲行程".into();
                return;
            }
        };
        let live = read_name(p, obj);
        if live != name || !sane_name(&live) {
            self.status = "寫入失敗：選手位址已失效，請先重新整理".into();
            return;
        }
        let ok = p.write(obj + off, &[nv]);
        if ok {
            self.research_loaded_byte = Some((obj, off, nv));
            self.status = format!(
                "任意 Offset：+0x{off:04X} 已寫入 0x{old:02X} → 0x{nv:02X}（{name}）"
            );
        } else {
            self.status = format!("任意 Offset：寫入 +0x{off:04X} 失敗");
        }
    }

    fn write_ok(&mut self, ok: bool, what: &str) {
        self.status = if ok {
            format!("已寫入 {what}　※切到別的選手再切回來畫面才會重畫")
        } else {
            format!("✗ 寫入失敗：{what}（位址可能已失效，按「重新整理」）")
        };
    }
}

/// 把第 n 個 nibble 寫回本地快照（記憶體那邊由 write_abil_nibble 負責）
fn set_nib(b: &mut [u8], n: usize, v: u8) {
    let i = n / 2;
    b[i] = if n % 2 == 0 { (b[i] & 0xF0) | (v & 0xF) } else { (b[i] & 0x0F) | (v << 4) };
}

/// 清單裡的一列：守備位置圖標 ＋ 姓名。回傳 true 表示被點選。
/// 整列都是點擊區（名字的 SelectableLabel 撐滿剩餘寬度）。
fn player_row(ui: &mut egui::Ui, pl: &Player, sel: bool, copies: usize, star: bool) -> bool {
    ui.horizontal(|ui| {
        ui.add_sized(
            [30.0, 18.0],
            egui::Label::new(
                egui::RichText::new(pos_name(pl.pos)).strong().color(pos_color(pl.pos)),
            ),
        );

        // 姓名與總評拆成固定寬度欄位；不再把兩者塞進同一個可變長字串。
        // 這樣每列的「總評」起點與三位數字都會垂直對齊。
        let name_txt = if star { format!("★ {}", pl.name) } else { pl.name.clone() };
        let name_resp = ui.add_sized(
            [92.0, 18.0],
            egui::SelectableLabel::new(sel, name_txt),
        );
        let overall_resp = ui.add_sized(
            [68.0, 18.0],
            egui::Label::new(egui::RichText::new(format!("總評 {:>3}", pl.overall())).monospace()),
        );
        if copies > 1 {
            ui.add_sized([34.0, 18.0], egui::Label::new(format!("×{copies}")));
        }

        let hover = if star {
            format!("物件 {:#x}\n★ 這份帶成長經驗值結構 ＝ 明星選手的主角，編輯要用這份", pl.addr)
        } else {
            format!("物件 {:#x}", pl.addr)
        };
        name_resp.clone().on_hover_text(&hover);
        overall_resp.on_hover_text(&hover);
        name_resp.clicked()
    })
    .inner
}

/// 栄冠「原始名單」的一列：保留 roster array 的原始 index，不做任何重新排序。
/// 左側顯示 #00..、守備位置、姓名與總評；欄位使用固定寬度。
fn raw_koshien_player_row(ui: &mut egui::Ui, index: usize, pl: &Player, sel: bool) -> bool {
    ui.horizontal(|ui| {
        ui.add_sized(
            [34.0, 18.0],
            egui::Label::new(egui::RichText::new(format!("#{index:02}")).monospace().weak()),
        );
        ui.add_sized(
            [30.0, 18.0],
            egui::Label::new(
                egui::RichText::new(pos_name(pl.pos)).strong().color(pos_color(pl.pos)),
            ),
        );
        let name_resp = ui.add_sized(
            [92.0, 18.0],
            egui::SelectableLabel::new(sel, pl.name.clone()),
        );
        let overall_resp = ui.add_sized(
            [68.0, 18.0],
            egui::Label::new(egui::RichText::new(format!("總評 {:>3}", pl.overall())).monospace()),
        );
        let hover = format!(
            "Roster index #{index:02}\n守備位置：{}\nPlayer Object {:#x}",
            pos_name(pl.pos),
            pl.addr
        );
        name_resp.clone().on_hover_text(&hover);
        overall_resp.on_hover_text(&hover);
        name_resp.clicked()
    })
    .inner
}

/// G~S 由低到高（`grade_btn` 的選項表）
const GS_OPTS: [(u8, &str); 8] = [
    (0, "G"), (1, "F"), (2, "E"), (3, "D"), (4, "C"), (5, "B"), (6, "A"), (7, "S"),
];

/// 等級字母的底色，比照遊戲畫面
fn grade_color(t: &str) -> egui::Color32 {
    match t {
        "S" => egui::Color32::from_rgb(238, 238, 238),
        "A" => egui::Color32::from_rgb(246, 168, 208),
        "B" => egui::Color32::from_rgb(240, 112, 112),
        "C" => egui::Color32::from_rgb(246, 160, 62),
        "D" => egui::Color32::from_rgb(240, 205, 72),
        "E" => egui::Color32::from_rgb(182, 220, 92),
        "F" => egui::Color32::from_rgb(122, 190, 240),
        "G" => egui::Color32::from_rgb(184, 162, 212),
        _ => egui::Color32::from_gray(90),
    }
}

/// 等級（或任何有序選項）的共用控制項：**左鍵 +1、超過最高繞回最低**，右鍵開選單。
/// `opts` 由低到高排列。回傳 `Some(新值)` 表示有變動。
fn grade_btn(ui: &mut egui::Ui, v: u8, opts: &[(u8, &str)], w: f32) -> Option<u8> {
    let i = opts.iter().position(|&(x, _)| x == v);
    let txt = i.map(|k| opts[k].1).unwrap_or("?");
    let mut out = None;
    let resp = ui
        .add_sized(
            [w, 22.0],
            egui::Button::new(
                egui::RichText::new(txt).strong().color(egui::Color32::from_gray(20)),
            )
            .fill(grade_color(txt)),
        )
        .on_hover_text("左鍵：往上一級（超過最高會繞回最低）\n右鍵：直接選");
    if resp.clicked() {
        let k = i.map_or(0, |k| (k + 1) % opts.len());
        out = Some(opts[k].0);
    }
    resp.context_menu(|ui| {
        for &(val, t) in opts.iter().rev() {
            if ui.selectable_label(val == v, t).clicked() {
                out = Some(val);
                ui.close_menu();
            }
        }
    });
    out
}

/// 九宮格單格：**左鍵 +1、超過 +3 繞回 −3**，右鍵開選單。正紅負藍，比照遊戲。
fn zone_btn(ui: &mut egui::Ui, v: i8) -> Option<i8> {
    let (fill, fg) = if v > 0 {
        (egui::Color32::from_rgb(170, 38, 38), egui::Color32::WHITE)
    } else if v < 0 {
        (egui::Color32::from_rgb(38, 68, 176), egui::Color32::WHITE)
    } else {
        (egui::Color32::from_gray(48), egui::Color32::from_gray(190))
    };
    let txt = if v > 0 {
        format!("▲{v}")
    } else if v < 0 {
        format!("▼{}", -v)
    } else {
        "0".to_string()
    };
    let mut out = None;
    let resp = ui
        .add_sized(
            [54.0, 30.0],
            egui::Button::new(egui::RichText::new(txt).strong().color(fg)).fill(fill),
        )
        .on_hover_text("左鍵：+1（超過 +3 會繞回 −3）\n右鍵：直接選");
    if resp.clicked() {
        out = Some(if v >= 3 { -3 } else { v + 1 });
    }
    resp.context_menu(|ui| {
        for x in (-3i8..=3).rev() {
            let t = if x > 0 { format!("+{x}") } else { x.to_string() };
            if ui.selectable_label(v == x, t).clicked() {
                out = Some(x);
                ui.close_menu();
            }
        }
    });
    out
}

/// 守備位置圖標的顏色，比照遊戲畫面：投手紅／捕手藍紫／內野黃／外野綠
fn pos_color(v: u8) -> egui::Color32 {
    match v {
        0 => egui::Color32::from_rgb(235, 120, 120),
        1 => egui::Color32::from_rgb(150, 160, 235),
        2..=5 => egui::Color32::from_rgb(225, 190, 90),
        6..=8 => egui::Color32::from_rgb(120, 210, 130),
        _ => egui::Color32::GRAY,
    }
}

fn grade_of(v: u8) -> &'static str {
    match v {
        0..=19 => "G",
        20..=29 => "F",
        30..=39 => "E",
        40..=54 => "D",
        55..=69 => "C",
        70..=79 => "B",
        80..=89 => "A",
        _ => "S",
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _f: &mut eframe::Frame) {
        self.poll_scan(ctx);
        self.auto_refresh_koshien(ctx);
        self.auto_refresh_recruit_regions(ctx);

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("prospi 選手編輯器");
                ui.separator();
                // 先取值再畫，避免 &self.proc 的借用跟 self 的 &mut 方法打架
                let alive = self.proc_alive();
                let pid = self.proc.as_ref().map(|p| p.pid);
                match pid {
                    Some(id) if alive => {
                        ui.colored_label(egui::Color32::from_rgb(80, 200, 120),
                                         format!("已附加 pid {id}"));
                    }
                    Some(id) => {
                        ui.colored_label(egui::Color32::from_rgb(240, 170, 60),
                                         format!("pid {id} 已失效 —— 遊戲重開過了，按「重新附加」"));
                    }
                    None => {
                        ui.colored_label(egui::Color32::from_rgb(230, 100, 100), &self.err);
                    }
                }
                // ⚠ 一律顯示，不能只在完全沒附加時才給 —— 遊戲重開後 self.proc 仍是 Some
                //   （只是 handle 指向死掉的 pid），使用者會找不到重新附加的入口。
                if ui.button("重新附加").clicked() {
                    self.proc = None;
                    self.growth_base = None;
                    self.reload_list();
                }
                ui.separator();
                let mut m = self.mode;
                ui.selectable_value(&mut m, Mode::Koshien, "栄冠(高中)");
                ui.selectable_value(&mut m, Mode::Star, "明星選手(主角)")
                    .on_hover_text("只找主角 —— 用成長經驗值結構的門檻表定位, 約 5 秒。\n\
                                    找不到就退回全記憶體掃描。");
                ui.selectable_value(&mut m, Mode::Scan, "明星選手(全掃)");
                if m != self.mode {
                    self.mode = m;
                    self.reload_list();
                }
                if ui.button("重新整理").clicked() {
                    self.reload_list();
                }
            });

            // ── 球種庫：跟選中哪位選手無關，所以放在頂端一直可見
            //    （原本放在選手資訊頁的收合區裡，沒選到選手就完全看不到）
            ui.horizontal(|ui| {
                let empty = self.lib.is_empty();
                let btn = egui::Button::new(
                    egui::RichText::new("⟳  蒐集原創球種到球種庫").strong(),
                )
                .fill(if empty {
                    egui::Color32::from_rgb(150, 100, 30)
                } else {
                    egui::Color32::from_rgb(52, 110, 72)
                });
                if ui
                    .add_sized([220.0, 26.0], btn)
                    .on_hover_text(
                        "把目前清單裡的選手身上的原創球種記錄加進球種庫並存檔。\n\
                         內附的球種庫只有官方球種；你自己用遊戲內編輯器做的球種\n\
                         要按這裡才會進到庫裡，之後就能套用到任何選手身上。\n\n\
                         依名稱去重，已經有的不會重複加。\n\
                         蒐集到多少取決於當下載入了哪些選手 ——\n\
                         想一次蒐集最多，先切到「明星選手(全掃)」再按。",
                    )
                    .clicked()
                {
                    self.collect_lib();
                }
                let n_custom = self.lib.iter().filter(|e| e.kind == "自訂").count();
                if empty {
                    ui.colored_label(
                        egui::Color32::from_rgb(240, 190, 100),
                        format!("球種庫是空的（找過 {}）—— 按左邊可以從遊戲裡重建",
                                self.libpath.display()),
                    );
                } else {
                    ui.label(format!("球種庫 {} 筆（官方 {}／自訂 {}）",
                                     self.lib.len(), self.lib.len() - n_custom, n_custom));
                    ui.weak(format!("來源：清單 {} 位選手", self.list.len()));
                }
                // 蒐集得到多少完全看當下清單有誰 —— 其他模式的清單小很多,
                // 所以直接把「先切到全掃」講在畫面上, 不要只寫在 hover 裡。
                if self.mode != Mode::Scan {
                    ui.colored_label(
                        egui::Color32::from_rgb(240, 190, 100),
                        "※ 建議先切到「明星選手(全掃)」再按，蒐集得到的球種最多",
                    );
                }
            });
            if self.scan_rx.is_some() {
                let (d, t) = self.scan_prog;
                ui.add(egui::ProgressBar::new(d as f32 / t as f32)
                    .text(format!("掃描中 {d}/{t} MB")));
            }
            if !self.status.is_empty() {
                ui.label(&self.status);
            }
        });

        // 常規功能：不依賴選中的選手，所以獨立成底部面板一直可見
        egui::TopBottomPanel::bottom("cheats").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("常規功能").strong());
                if self.cheats.any_on() {
                    let t = self.cheats.ticks.load(Ordering::Relaxed);
                    ui.colored_label(
                        egui::Color32::from_rgb(80, 200, 120),
                        egui::RichText::new(format!("持續套用中（每 0.3 秒重寫．已 {t} 輪）")).small());
                    // 沒有這行的話視窗失焦就不重繪，心跳會看起來卡住（實際上執行緒還在跑）
                    ctx.request_repaint_after(std::time::Duration::from_millis(500));
                } else {
                    ui.label(egui::RichText::new("勾了就持續生效，不必再按任何按鈕")
                        .weak().small());
                }
            });
            ui.horizontal_wrapped(|ui| {
                cheat_box(ui, &self.cheats.koshien_items,
                    "栄冠：全道具 99 ＋ 使用不消耗",
                    "221 格道具全部寫 99 並持續維持。\n\
                     每 0.3 秒就補回去，所以用掉也會立刻回滿 ＝ 等同不消耗，\
                     不必像 CT 那樣去 hook 扣除的那行程式碼。\n\
                     ⚠ 要在有部員名單的畫面才有效（離開栄冠模式時指標鏈會變 0）。");
                cheat_box(ui, &self.cheats.koshien_limit,
                    "栄冠：解除「每人 1 個道具 / 書籍 5 本」",
                    "把每位部員的 +0x1511 / +0x1512 持續歸零 —— 上限判斷讀的就是這兩個 byte。");
                cheat_box(ui, &self.cheats.koshien_prac,
                    "栄冠：練習效果提升永久",
                    "把「練習效果提升中」的剩餘天數持續寫回 9999（道具物件 +0x382，i16）。\n\
                     畫面顯示夾在 99，但內部真的是 9999、照常每天 −1。\n\
                     ⚠ 觸發經理事件時遊戲會把這個值夾回 99，所以才需要持續維持；\
                     若你不會再觸發，用右邊的按鈕寫一次就夠（9999 天 ≈ 27 遊戲年）。\n\
                     ⚠ 要在栄冠模式（有部員名單的畫面）才有效。");
                cheat_box(ui, &self.cheats.shared_items,
                    "跨模式：共用道具全 99",
                    "i32×49，含栄冠 UI 最後 11 格與明星選手的 7 種，任何模式都能寫。\n\
                     ⚠ 這個靜態位址**會隨版本搬家**（2026-08-27 更新從 exe+1974D280 \
                     搬到 exe+19AECCE0）——lib 端列了候選並用值域驗證，會自動挑有效的那個。");
                cheat_box(ui, &self.cheats.star_items,
                    "明星選手：道具使用次數保持 0",
                    "把使用次數陣列的道具區間（index 3..9）持續歸零 ——                      UI 的「已使用 N」讀的就是它，所以永遠是 0 ＝ 無限使用。\n                     2026-08-29 用 pscan xref 從計數函式往回追到靜態指標 exe+1999C138，                     已在遊戲畫面驗證過因果（清 0 後 UI 跟著變 0）。\n                     ⚠ 要在明星選手模式（讀過存檔）才有效。\n                     ★ 這取代了舊的「nop 掉 inc al」——那條是通用計數器，                     xref 查出有 18 個呼叫端，nop 掉會波及無關的計數。");
            });
            // 值本身一天才減 1，不勾也行 —— 但觸發經理事件時遊戲會夾回 99，
            // 所以「按一次」只適合之後不再觸發的情況，兩種都留給使用者選。
            ui.horizontal_wrapped(|ui| {
                if ui.button("栄冠：練習效果提升 → 9999 天（單次）")
                    .on_hover_text(
                        "把「練習效果提升中」的剩餘天數寫成 9999（道具物件 +0x382，i16）。\n\
                         畫面顯示夾在 99，但內部真的是 9999、照常每天 −1 —— \
                         9999 遊戲天 ≈ 27 年，一場栄冠才 3 年。\n\
                         ⚠ 之後只要再觸發經理事件，遊戲就會把它夾回 99，\
                         那種情況請改勾左邊的「練習效果提升永久」。\n\
                         ⚠ 要在栄冠模式（有部員名單的畫面）才有效。\n\
                         ⚠ 記憶體修改不進存檔，重讀存檔後要再按一次。")
                    .clicked()
                {
                    if self.ensure_proc() {
                        let done = self.proc.as_ref()
                            .is_some_and(|p| set_koshien_pracbuff(p, KOSHIEN_PRACBUFF_DAYS));
                        self.status = if done {
                            format!("已把練習效果提升設成 {KOSHIEN_PRACBUFF_DAYS} 天（畫面會顯示 99）")
                        } else {
                            "寫入失敗 —— 目前不在栄冠模式（指標鏈是 0），\
                             請在有部員名單的畫面再按一次".into()
                        };
                    }
                }

                if ui.button("榮冠：所有球員情緒 → 超興奮（單次）")
                    .on_hover_text(
                        "把目前榮冠 roster 中所有部員的情緒一次設成「超興奮」。\n\
                         寫入 Player Object +0xE82 = 0。\n\
                         執行前會先完整驗證 roster count、每個 Player Object 與姓名；\n\
                         任一項異常就整批取消，不會寫入任何球員。\n\
                         這是單次修改；之後遊戲事件若改變情緒，需要再按一次。")
                    .clicked()
                {
                    if self.ensure_proc() {
                        let checked = self.proc.as_ref()
                            .map(|p| validated_koshien_roster(p))
                            .unwrap_or_else(|| Err("尚未附加遊戲".into()));
                        match checked {
                            Ok(roster) => {
                                let expected = roster.len();
                                let n = self.proc.as_ref()
                                    .map_or(0, |p| set_koshien_all_mood(p, 0));
                                if n == expected && n > 0 {
                                    for pl in &mut self.list {
                                        if roster.contains(&pl.addr) {
                                            pl.mood = 0;
                                        }
                                    }
                                    if let Some(cur) = self.cur.as_mut() {
                                        if roster.contains(&cur.addr) {
                                            cur.mood = 0;
                                        }
                                    }
                                    self.status = format!("已將 {n} 位榮冠球員情緒設為超興奮");
                                } else {
                                    self.status = format!("寫入未完整完成（成功 {n}/{expected}），請重新取得名單後再試");
                                }
                            }
                            Err(e) => {
                                self.status = format!("未進行修改 —— {e}");
                            }
                        }
                    }
                }
            });
            ui.add_space(3.0);
        });

        egui::SidePanel::left("list").resizable(true).default_width(250.0).show(ctx, |ui| {
            // 只有栄冠有固定 roster array，因此只有栄冠提供「排序／原始」兩種頁籤。
            // 明星選手模式仍維持既有掃描結果顯示，不受此功能影響。
            if self.mode == Mode::Koshien {
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut self.koshien_roster_view,
                        KoshienRosterView::Sorted,
                        "已排序名單",
                    );
                    ui.selectable_value(
                        &mut self.koshien_roster_view,
                        KoshienRosterView::Raw,
                        "原始名單",
                    )
                    .on_hover_text("完全照遊戲 roster array 的 index 0..N-1 顯示，不依守備位置重新排序");
                    ui.selectable_value(
                        &mut self.koshien_roster_view,
                        KoshienRosterView::Recruit,
                        "新生招募",
                    )
                    .on_hover_text("依 Region index 讀取該地區 10 位候選球員");
                });
                ui.separator();
            }

            let recruit_view = self.mode == Mode::Koshien
                && self.koshien_roster_view == KoshienRosterView::Recruit;

            // 招募／天才機率放在「新生招募」分頁內顯示，但它們都是直接修改 exe 的 runtime patch，
            // 與 Region / Candidate Object 是否已生成完全無關。
            // 即使目前沒有任何可招募地區／候選球員，也必須允許隨時操作。
            if recruit_view {
                // 天才出現機率：直接修改原生 `cmp eax,1` 的門檻，0..100 對應 0%..100%。
                ui.label("天才出現機率（招募與新生，轉生除外）");
                ui.horizontal(|ui| {
                    let mut v = self.talent_rate.min(100);
                    let slider_changed = ui
                        .add(egui::Slider::new(&mut v, 0..=100).show_value(false))
                        .changed();
                    let input_changed = ui
                        .add(egui::DragValue::new(&mut v).range(0..=100).speed(1.0))
                        .changed();
                    ui.label("%");

                    if slider_changed || input_changed {
                        v = v.min(100);
                        if let Some(p) = self.proc.as_ref() {
                            match set_talent_rate(p, v) {
                                Ok(()) => {
                                    self.talent_rate = v;
                                    self.status = format!("天才出現機率 → {v}%");
                                }
                                Err(e) => self.status = format!("天才機率修改失敗：{e}"),
                            }
                        } else {
                            self.status = "尚未附加遊戲行程，無法修改天才出現機率".into();
                        }
                    }

                    // 只讀取目前遊戲 Process 的實際天才機率並同步 UI，不寫入。
                    if ui.button("刷新").clicked() {
                        if let Some(p) = self.proc.as_ref() {
                            match talent_rate(p) {
                                Some(rate) => {
                                    self.talent_rate = rate;
                                    self.status = format!("已讀取目前天才出現機率：{rate}%");
                                }
                                None => self.status = "讀取目前天才出現機率失敗".into(),
                            }
                        } else {
                            self.status = "尚未附加遊戲行程，無法刷新天才出現機率".into();
                        }
                    }

                    // 一鍵恢復遊戲原生天才機率 1%。
                    if ui.button("恢復原始機率").clicked() {
                        if let Some(p) = self.proc.as_ref() {
                            match set_talent_rate(p, TALENT_RATE_DEFAULT) {
                                Ok(()) => {
                                    self.talent_rate = TALENT_RATE_DEFAULT;
                                    self.status = format!("天才出現機率已恢復為原始 {}%", TALENT_RATE_DEFAULT);
                                }
                                Err(e) => self.status = format!("恢復天才原始機率失敗：{e}"),
                            }
                        } else {
                            self.status = "尚未附加遊戲行程，無法恢復天才原始機率".into();
                        }
                    }
                });

                ui.horizontal(|ui| {
                    let mut want = self.recruit_rate_100;
                    if ui.checkbox(&mut want, "招募機率100%").changed() {
                        if let Some(p) = self.proc.as_ref() {
                            match set_recruit_rate_100(p, want) {
                                Ok(()) => {
                                    self.recruit_rate_100 = want;
                                    self.status = if want {
                                        "已啟用招募機率 100%".into()
                                    } else {
                                        "已還原原始招募機率".into()
                                    };
                                }
                                Err(e) => self.status = format!("招募機率修改失敗：{e}"),
                            }
                        } else {
                            self.status = "尚未附加遊戲行程，無法修改招募機率".into();
                        }
                    }

                    // 手動安全復原：只有 restore 成功後才取消 checkbox。
                    // 與「取消勾選」及 App::drop() 共用同一個資料表 restore function。
                    if ui.button("恢復原始招募機率").clicked() {
                        if let Some(p) = self.proc.as_ref() {
                            match reset_recruit_rate_patch(p) {
                                Ok(true) => {
                                    self.recruit_rate_100 = false;
                                    self.status = "招募機率已重設為遊戲原始值".into();
                                }
                                Ok(false) => {
                                    // 本 instance 沒有 active patch：不碰遊戲資料，也不偽裝成已還原。
                                    self.status = "招募機率目前沒有由本修改器套用的 100% patch".into();
                                }
                                Err(e) => {
                                    // 還原失敗時維持原 checkbox 狀態，避免 UI 與遊戲記憶體不一致。
                                    self.status = format!("招募機率重設失敗：{e}");
                                }
                            }
                        } else {
                            self.status = "尚未附加遊戲行程，無法重設招募機率".into();
                        }
                    }
                });
                ui.separator();
            }

            if recruit_view {
                // 第一次進入新生招募頁時才立即嘗試讀一次；
                // 若目前沒有候選人，不要每幀重跑並覆蓋其他功能的狀態訊息。
                // 後續由 auto_refresh_recruit_regions() 每 2 秒自動偵測與同步。
                if self.recruit_regions.is_empty() && self.recruit_loaded_region.is_none() {
                    self.reload_recruits();
                }
                let old_region = self.recruit_region;

                ui.horizontal(|ui| {
                    ui.label("可招募的地區");
                    let shown = if self.recruit_regions.contains(&self.recruit_region) {
                        recruit_region_label(self.recruit_region)
                    } else {
                        "無".to_string()
                    };
                    // egui 會記住 ComboBox popup / ScrollArea 的 UI state。若修改器啟動時只有
                    // 1~3 個地區，之後動態增加，固定 ID 會沿用第一次建立時的低高度，
                    // 導致第 4 個就開始捲動。讓 ID 隨「目前可見列數」變化即可強制重建 popup；
                    // 7 個以上維持 visible_rows=6，因此從第 7 個開始才正常使用 scroll。
                    let visible_rows = self.recruit_regions.len().clamp(1, 6);
                    let row_height = ui.spacing().interact_size.y;
                    let row_gap = ui.spacing().item_spacing.y;
                    let popup_height = row_height * 6.0 + row_gap * 5.0;
                    egui::ComboBox::from_id_source(("recruit_region", visible_rows))
                        .selected_text(shown)
                        .width(150.0)
                        .height(popup_height)
                        .show_ui(ui, |ui| {
                            let regions = self.recruit_regions.clone();
                            for r in regions {
                                ui.selectable_value(&mut self.recruit_region, r, recruit_region_label(r));
                            }
                        });
                });
                if self.recruit_region != old_region
                    || self.recruit_loaded_region != Some(self.recruit_region)
                {
                    self.reload_recruits();
                }
                ui.separator();

                let mut pick: Option<usize> = None;
                egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                    for (row, e) in self.recruit_list.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.add_sized(
                                [34.0, 18.0],
                                egui::Label::new(egui::RichText::new(format!("#{:02}", e.index)).monospace().weak()),
                            );
                            ui.add_sized(
                                [30.0, 18.0],
                                egui::Label::new(
                                    egui::RichText::new(pos_name(e.player.pos)).strong().color(pos_color(e.player.pos)),
                                ),
                            );
                            // 跟一般球員清單一致：姓名與總評使用固定寬度欄位。
                            let name_resp = ui.add_sized(
                                [92.0, 18.0],
                                egui::SelectableLabel::new(self.recruit_sel == Some(row), &e.player.name),
                            );
                            let overall_resp = ui.add_sized(
                                [68.0, 18.0],
                                egui::Label::new(
                                    egui::RichText::new(format!("總評 {:>3}", e.player.overall())).monospace(),
                                ),
                            );
                            let hover = format!(
                                "Region {} / Candidate #{}\nCandidate: 0x{:X}\nPlayer Object: 0x{:X}",
                                self.recruit_region, e.index, e.candidate_addr, e.player.addr
                            );
                            name_resp.clone().on_hover_text(&hover);
                            overall_resp.on_hover_text(&hover);
                            if name_resp.clicked() {
                                pick = Some(row);
                            }
                        });
                    }
                });
                if let Some(row) = pick {
                    self.recruit_sel = Some(row);
                    self.recruit_cur = self.recruit_list.get(row).map(|e| e.player.clone());
                }
            } else {

            ui.horizontal(|ui| {
                ui.label("搜尋");
                ui.text_edit_singleline(&mut self.filter);
            });
            // ⚠ 原本是「球速≥120」—— 但野手的球速欄一律是 120，等於完全沒過濾。
            //   改用 +0xEB6 的守備位置。
            ui.checkbox(&mut self.only_pitchers, "只顯示投手");

            // 原始名單的目的就是忠實顯示 roster index，因此不套用「合併同名副本」。
            // 其他模式與栄冠的已排序名單維持既有行為。
            let raw_koshien = self.mode == Mode::Koshien
                && self.koshien_roster_view == KoshienRosterView::Raw;
            if !raw_koshien {
                ui.checkbox(&mut self.merge_dups, "合併同名副本")
                    .on_hover_text("同一位選手在記憶體裡有 2~4 份（不同世代／不同用途）。\n勾起來時同隊同名只留位址最小的那份，右邊會標「×份數」。\n⚠ 挑哪一份是經驗法則（12 位對照畫面值中 11 位正確），\n　 改了畫面沒反應就取消勾選、換一份試。");
            } else {
                ui.weak(format!("Roster 原始順序：{} 人（index 0..{}）",
                    self.list.len(), self.list.len().saturating_sub(1)));
            }
            ui.separator();

            // auto_shrink=false：否則每列是 horizontal（內容寬），ScrollArea 會跟著縮，
            // 面板右半邊會空一大塊出來
            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                let f = self.filter.trim().to_lowercase();
                let mut newsel = None;

                if raw_koshien {
                    // 栄冠原始名單：直接走 self.list 的原始 roster 順序。
                    // 搜尋／只顯示投手只做「過濾」，絕不改變剩餘項目的 index 或次序。
                    for (i, pl) in self.list.iter().enumerate() {
                        if !f.is_empty() && !pl.name.to_lowercase().contains(&f) {
                            continue;
                        }
                        if self.only_pitchers && pl.pos != 0 {
                            continue;
                        }
                        if raw_koshien_player_row(ui, i, pl, self.sel == Some(i)) {
                            newsel = Some(i);
                        }
                    }
                } else {
                    // 既有顯示方式：依守備位置分組（P→C→1B→2B→3B→SS→LF→CF→RF），
                    // 組內能力高的在前。只排序 UI 的 order，self.list 原始順序永遠不動。
                    let mut order: Vec<usize> = (0..self.list.len())
                        .filter(|&i| {
                            let pl = &self.list[i];
                            (f.is_empty() || pl.name.to_lowercase().contains(&f))
                                && !(self.only_pitchers && pl.pos != 0)
                        })
                        .collect();
                    order.sort_by_key(|&i| {
                        let pl = &self.list[i];
                        let strength = if pl.pos == 0 { pl.speed as i32 } else { pl.stats[0] as i32 };
                        (pl.pos, -strength)
                    });

                    let mut copies: std::collections::HashMap<usize, usize> =
                        std::collections::HashMap::new();
                    if self.merge_dups {
                        order.retain(|&i| {
                            let pl = &self.list[i];
                            match self.dup_rep.get(&(pl.team, pl.name.clone())) {
                                Some(&(rep, n)) if rep == i => {
                                    copies.insert(i, n);
                                    true
                                }
                                Some(_) => false,
                                None => true,
                            }
                        });
                    }

                    if self.mode == Mode::Koshien {
                        let mut last_pos: Option<u8> = None;
                        for i in order {
                            if last_pos.is_some_and(|p| p != self.list[i].pos) {
                                ui.separator();
                            }
                            last_pos = Some(self.list[i].pos);
                            if player_row(
                                ui,
                                &self.list[i],
                                self.sel == Some(i),
                                copies.get(&i).copied().unwrap_or(1),
                                self.growth_owners.contains(&i),
                            ) {
                                newsel = Some(i);
                            }
                        }
                    } else {
                        // 明星選手：完全維持原本的「先分隊、隊內依守備位置」顯示方式。
                        let mut by_team: std::collections::BTreeMap<u8, Vec<usize>> =
                            std::collections::BTreeMap::new();
                        for &i in &order {
                            by_team.entry(self.list[i].team).or_default().push(i);
                        }
                        for (tid, idxs) in by_team {
                            let label = match self.teams.get(&tid) {
                                Some(n) => format!("{n}　{} 人", idxs.len()),
                                None => format!(
                                    "隊伍 {tid}　{} 人　（{}…）",
                                    idxs.len(),
                                    self.list[idxs[0]].name
                                ),
                            };
                            let mut head =
                                egui::CollapsingHeader::new(label).id_source(("team", tid));
                            if !f.is_empty() {
                                head = head.open(Some(true));
                            }
                            head.show(ui, |ui| {
                                if self.rename_team == Some(tid) {
                                    let r = ui.text_edit_singleline(&mut self.rename_buf);
                                    let done = r.lost_focus()
                                        && ui.input(|i| i.key_pressed(egui::Key::Enter));
                                    if done || ui.small_button("✔ 儲存").clicked() {
                                        let v = self.rename_buf.trim().to_string();
                                        if v.is_empty() {
                                            self.teams.remove(&tid);
                                        } else {
                                            self.teams.insert(tid, v);
                                        }
                                        self.rename_team = None;
                                        self.status = match save_teams(&teams_path(), &self.teams) {
                                            Ok(()) => format!("已存隊名 → {}", teams_path().display()),
                                            Err(e) => e,
                                        };
                                    }
                                } else {
                                    let hint = &self.list[idxs[0]].name;
                                    if ui
                                        .small_button(format!("✎ 命名（例如：{hint} 那一隊）"))
                                        .on_hover_text(
                                            "遊戲記憶體裡沒有隊伍 ID 對隊名的表, \
                                             所以隊名要自己填一次, 之後會記在 teams.json。",
                                        )
                                        .clicked()
                                    {
                                        self.rename_team = Some(tid);
                                        self.rename_buf =
                                            self.teams.get(&tid).cloned().unwrap_or_default();
                                    }
                                }
                                for &i in &idxs {
                                    if player_row(
                                        ui,
                                        &self.list[i],
                                        self.sel == Some(i),
                                        copies.get(&i).copied().unwrap_or(1),
                                        self.growth_owners.contains(&i),
                                    ) {
                                        newsel = Some(i);
                                    }
                                }
                            });
                        }
                    }
                }

                if let Some(i) = newsel {
                    self.sel = Some(i);
                    self.reload_current();
                }
            });
            } // !recruit_view
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let recruit_view = self.mode == Mode::Koshien
                && self.koshien_roster_view == KoshienRosterView::Recruit;
            if recruit_view {
                if self.recruit_cur.is_none() {
                    ui.centered_and_justified(|ui| ui.label("← 從左邊選一位候選球員"));
                    return;
                }
                egui::ScrollArea::vertical().show(ui, |ui| self.recruit_editor(ui));
            } else {
                if self.cur.is_none() {
                    ui.centered_and_justified(|ui| ui.label("← 從左邊選一位選手"));
                    return;
                }
                egui::ScrollArea::vertical().show(ui, |ui| self.editor(ui));
            }
        });
    }
}

impl App {
    /// 新生招募候選人只顯示/編輯已確認與一般 Player Object 共用的區域：
    /// 主守位、投手/野手守備適性、八項能力、球速/耐力、捕手配球、特殊能力。
    /// 不顯示性格/學力/年級等尚未確認能否直接沿用的欄位。
    fn recruit_editor(&mut self, ui: &mut egui::Ui) {
        let mut cur = match self.recruit_cur.clone() { Some(v) => v, None => return };
        let obj = cur.addr;
        let mut act: Option<(bool, String)> = None;
        let mut manual_reload = false;
        macro_rules! P { () => { match &self.proc { Some(p) => p, None => return } }; }

        let (cand_index, cand_addr) = self.recruit_sel
            .and_then(|i| self.recruit_list.get(i).map(|e| (e.index, e.candidate_addr)))
            .unwrap_or((0, obj.saturating_sub(RECRUIT_PLAYER_FROM_CANDIDATE)));
        ui.horizontal(|ui| {
            ui.heading(&cur.name);
            ui.colored_label(pos_color(cur.pos), egui::RichText::new(pos_name(cur.pos)).strong());
            ui.monospace(format!(
                "Region {} / Candidate #{}  |  C=0x{:X}  P=0x{:X}",
                self.recruit_region, cand_index, cand_addr, obj
            ));
            if ui.button("重新讀取").clicked() {
                if let Some(pl) = Player::load(P!(), obj) {
                    cur = pl;
                    manual_reload = true;
                }
            }
        });
        ui.separator();

        // 只用 raw Player Object 欄位，不碰一般部員的成長經驗值同步區。
        egui::CollapsingHeader::new("投手能力／守備適性").default_open(true).show(ui, |ui| {
            egui::Grid::new("recruit_basic").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label("主要守備位置");
                let old_pos = cur.pos;
                egui::ComboBox::from_id_source(("recruit_main_pos", obj))
                    .selected_text(pos_name(cur.pos)).width(90.0).show_ui(ui, |ui| {
                        for (v, name) in POS_NAMES.iter().enumerate() {
                            ui.selectable_value(&mut cur.pos, v as u8, *name);
                        }
                    });
                if cur.pos != old_pos {
                    let ok = write_pos(P!(), obj, cur.pos);
                    act = Some((ok, format!("主要守備位置 → {}", pos_name(cur.pos))));
                }
                ui.end_row();

                // 候選球員打擊仰角／打球型態：沿用已驗證的 Player Object 真值欄位。
                ui.label("打擊仰角");
                let old_style = cur.batting_style;
                egui::ComboBox::from_id_source(("recruit_batting_style", obj))
                    .selected_text(batting_style_name(cur.batting_style))
                    .width(130.0)
                    .show_ui(ui, |ui| {
                        for (v, name) in BATTING_STYLE_NAMES.iter().enumerate() {
                            ui.selectable_value(&mut cur.batting_style, v as u8, *name);
                        }
                    });
                if cur.batting_style != old_style && cur.batting_style != BATTING_STYLE_UNKNOWN {
                    let ok = write_batting_style(P!(), obj, cur.batting_style);
                    act = Some((ok, format!("打擊仰角 → {}", batting_style_name(cur.batting_style))));
                }
                ui.end_row();

                // 候選人天才：Player Object +0xE3C bit1（Candidate +0xE54 bit1），已實機確認。
                ui.label("天才");
                let mut talent = player_is_talent(P!(), obj);
                if ui.checkbox(&mut talent, "").changed() {
                    let ok = write_player_talent(P!(), obj, talent);
                    act = Some((ok, if talent { "天才 → 是".into() } else { "天才 → 否".into() }));
                }
                ui.end_row();

                ui.label("球速 km/h");
                if ui.add(egui::Slider::new(&mut cur.speed, 80..=SPEED_UI_MAX)).changed() {
                    let ok = write_pack(P!(), obj, cur.speed, cur.stamina, cur.pack_hi);
                    act = Some((ok, "球速".into()));
                }
                ui.end_row();
                ui.label("耐力");
                if ui.add(egui::Slider::new(&mut cur.stamina, 0..=99)).changed() {
                    let ok = write_pack(P!(), obj, cur.speed, cur.stamina, cur.pack_hi);
                    act = Some((ok, "耐力".into()));
                }
                ui.end_row();
                ui.label("投手適性");
                if ui.add(egui::Slider::new(&mut cur.defense, 0..=99)).changed() {
                    let ok = P!().write(obj + OFF_DEF, &[cur.defense]);
                    act = Some((ok, "投手適性".into()));
                }
                ui.end_row();

                for fi in 0..GROWTH_FIELD_N {
                    ui.label(FIELD_NAMES[fi]);
                    if ui.add(egui::Slider::new(&mut cur.field[fi], 0..=99)).changed() {
                        let ok = P!().write(obj + 0x18 + fi, &[cur.field[fi]]);
                        act = Some((ok, FIELD_NAMES[fi].into()));
                    }
                    ui.end_row();
                }

                ui.label("捕手配球");
                if let Some(g) = grade_btn(ui, cur.catcher, &GS_OPTS, 52.0) {
                    cur.catcher = g;
                    let ok = write_catcher(P!(), obj, g);
                    act = Some((ok, "捕手配球".into()));
                }
                ui.end_row();
            });
        });

        egui::CollapsingHeader::new("野手能力").default_open(true).show(ui, |ui| {
            egui::Grid::new("recruit_stats").num_columns(3).spacing([12.0, 6.0]).show(ui, |ui| {
                for i in 0..8 {
                    ui.label(STAT_NAMES[i]);
                    let mut v = cur.stats[i];
                    if ui.add(egui::Slider::new(&mut v, 1..=STAT_UI_MAX)).changed() {
                        cur.stats[i] = v;
                        let ok = P!().write(obj + OFF_STATS + i, &[v]);
                        act = Some((ok, STAT_NAMES[i].into()));
                    }
                    ui.label(grade_of(cur.stats[i]));
                    ui.end_row();
                }
            });
        });

        egui::CollapsingHeader::new("特殊能力").default_open(true).show(ui, |ui| {
            ui.label(egui::RichText::new("等級能力").strong());
            egui::Grid::new("recruit_abil_graded").num_columns(3).spacing([10.0, 4.0]).show(ui, |ui| {
                for &n in ABIL_GRADED {
                    let optional = ABIL_GRADED_OPTIONAL.contains(&n);
                    let nib = abil_nib(&cur.abil, n);
                    let (lv, extra) = (nib & 7, nib & 8 != 0);
                    ui.label(abil_name(n));
                    let mut opts: Vec<(u8, &str)> = vec![(5,"G"),(6,"F"),(7,"E"),(0,"D"),(1,"C"),(2,"B"),(3,"A")];
                    if optional { opts.retain(|&(v,_)| v != 0); opts.insert(0,(0,"（無）")); }
                    if let Some(newlv) = grade_btn(ui, lv, &opts, 78.0) {
                        let nv = (nib & 8) | newlv;
                        let ok = write_abil_nibble(P!(), obj, n, nv);
                        set_nib(&mut cur.abil, n, nv);
                        act = Some((ok, format!("{} 等級", abil_name(n))));
                    }
                    let bit3 = ABIL_GRADED_BIT3.iter().find(|e| e.0 == n).map(|e| e.1).unwrap_or("");
                    let mut on = extra;
                    if !bit3.is_empty() && ui.checkbox(&mut on, bit3).changed() {
                        let nv = (nib & 7) | if on { 8 } else { 0 };
                        let ok = write_abil_nibble(P!(), obj, n, nv);
                        set_nib(&mut cur.abil, n, nv);
                        act = Some((ok, bit3.into()));
                    }
                    ui.end_row();
                }
            });
            ui.separator();
            ui.label(egui::RichText::new("變體能力").strong());
            egui::Grid::new("recruit_abil_bits").num_columns(5).spacing([8.0,3.0]).show(ui, |ui| {
                for n in 0..ABIL_NIBBLES {
                    if abil_is_graded(n) { continue; }
                    let nib = abil_nib(&cur.abil, n);
                    ui.label(egui::RichText::new(format!("n{n:<2}")).weak().small());
                    for b in 0..4u8 {
                        let name = ABIL_BITS.iter().find(|e| e.0 == n && e.1 == b).map(|e| e.2).unwrap_or("—");
                        let mut on = nib >> b & 1 == 1;
                        if ui.add_enabled(name != "—", egui::Checkbox::new(&mut on, name)).changed() {
                            let nv = if on { nib | 1 << b } else { nib & !(1 << b) };
                            let ok = write_abil_nibble(P!(), obj, n, nv);
                            set_nib(&mut cur.abil, n, nv);
                            act = Some((ok, name.into()));
                        }
                    }
                    ui.end_row();
                }
            });
            ui.label(egui::RichText::new(format!(
                "現值 {}", cur.abil.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
            )).weak().small().monospace());
        });

        // 候選人也採用與一般球員相同的同步原則：
        // - 修改器自己寫入時，立即更新左側 recruit_list 的 overall。
        // - 手動「重新讀取」時，也把新快照同步到左側。
        // - 平常絕不每幀把 recruit_cur 灌回 recruit_list；遊戲自行成長由 2 秒同步負責。
        if act.is_some() || manual_reload {
            if let Some(i) = self.recruit_sel {
                if let Some(e) = self.recruit_list.get_mut(i) {
                    if e.player.addr == cur.addr {
                        e.player = cur.clone();
                    }
                }
            }
        }
        if let Some((ok, what)) = act {
            self.status = if ok { format!("新生招募：已寫入 {what}") } else { format!("新生招募：寫入失敗 {what}") };
        }
        self.recruit_cur = Some(cur);
    }

    fn editor(&mut self, ui: &mut egui::Ui) {
        let mut cur = self.cur.clone().unwrap();
        let obj = cur.addr;
        let mut act: Option<(bool, String)> = None;
        // ⚠ cur 是進來時的快照。只要動到「原創球種記錄陣列」或球種 ID，
        //   就必須從記憶體重讀 —— 否則「找一筆空記錄」會一直回傳同一個索引，
        //   連續設定多個方向的原創球種時會全部蓋在同一筆上（只有最後一顆會生效）。
        let mut need_reload = false;
        // 這位選手的所有副本（同隊同名），依位址排序 —— 給標題列的 ◀ ▶ 用
        let mut switch: Option<usize> = None;
        let sibs: Vec<usize> = {
            let mut v: Vec<usize> = (0..self.list.len())
                .filter(|&i| self.list[i].team == cur.team && self.list[i].name == cur.name)
                .collect();
            v.sort_by_key(|&i| self.list[i].addr);
            v
        };

        macro_rules! P {
            () => {
                match &self.proc { Some(p) => p, None => return }
            };
        }

        ui.horizontal(|ui| {
            ui.heading(&cur.name);
            ui.colored_label(pos_color(cur.pos), egui::RichText::new(pos_name(cur.pos)).strong());
            if self.mode != Mode::Koshien {
                let t = self
                    .teams
                    .get(&cur.team)
                    .cloned()
                    .unwrap_or_else(|| format!("隊伍 {}", cur.team));
                ui.label(t);
            }
            // 選中任何球員後都直接顯示實際 Player Object 位址。
            // 栄冠模式下 self.sel 仍是原始 roster array 的索引，即使左側目前採守備位置排序。
            if self.mode == Mode::Koshien {
                if let Some(i) = self.sel {
                    ui.monospace(format!("Roster #{i:02}  |  Player Object: 0x{obj:X}"));
                } else {
                    ui.monospace(format!("Player Object: 0x{obj:X}"));
                }
            } else {
                ui.monospace(format!("Player Object: 0x{obj:X}"));
            }
            if ui.button("重新讀取").clicked() {
                act = Some((true, "（重新讀取）".into()));
            }

            // ── 副本切換。「合併同名副本」是幫你挑了一份（同隊同名取位址最小），
            //    實測 12 位對照畫面值中 11 位正確 —— 挑錯時症狀是「改了畫面沒反應」，
            //    所以一定要留一個當場換一份的入口。
            if sibs.len() > 1 {
                ui.separator();
                let k = sibs.iter().position(|&i| Some(i) == self.sel).unwrap_or(0);
                if ui.small_button("◀").clicked() {
                    switch = Some(sibs[(k + sibs.len() - 1) % sibs.len()]);
                }
                ui.label(
                    egui::RichText::new(format!("副本 {}/{}", k + 1, sibs.len()))
                        .color(egui::Color32::from_rgb(240, 190, 100)),
                )
                .on_hover_text(
                    "這位選手在記憶體裡有多份。清單顯示的是位址最小的那一份，\n\
                     但不保證就是遊戲正在讀的那份。\n\
                     改了畫面沒反應 → 按 ◀ ▶ 換一份再改。",
                );
                if ui.small_button("▶").clicked() {
                    switch = Some(sibs[(k + 1) % sibs.len()]);
                }
            }
        });
        ui.separator();

        // 位址可能已經不屬於這位選手：遊戲重開，或明星選手模式讀了存檔後物件整批搬家。
        // 讀回姓名比對，對不上就整個停用 —— 否則接下來每個滑桿都會寫進別人的資料。
        let live = self.proc.as_ref().map(|p| read_name(p, obj)).unwrap_or_default();
        if live != cur.name || !sane_name(&live) {
            let shown = if live.trim().is_empty() { "（空白）" } else { live.as_str() };
            ui.colored_label(
                egui::Color32::from_rgb(240, 170, 60),
                format!("⚠ 這個位址現在讀到「{shown}」，不是 {} —— 遊戲重開或讀過存檔了。\n\
                         栄冠：按上方「重新整理」即可。明星選手：要重新掃描一次。",
                        cur.name));
            return;
        }

        // ── 鎖定（明星選手模式的成長結算會把能力值算回原值）
        ui.horizontal_wrapped(|ui| {
            let mut on = self.cheats.lock_player.load(Ordering::Relaxed);
            let changed = ui
                .checkbox(&mut on, "🔒 鎖定這位選手的數值（每 0.3 秒重寫）")
                .on_hover_text(
                    "明星選手模式的能力值有一份權威來源（成長／經驗值資料），\
                     我們改的只是它算出來的結果。\n\
                     打完比賽或推進日期時遊戲會重新結算並覆寫，還會報「力量已下降 23 了！」\
                     —— 所以單次寫入撐不到下一場。\n\
                     勾這個就每 0.3 秒把值重寫回去，遊戲蓋回來也會立刻被蓋回去。\n\
                     ⚠ 結算畫面仍會顯示「已下降 N」（那是遊戲自己比對快照），\
                     但過完那個畫面數值就會回到你設定的值。\n\
                     ⚠ 鎖定的是「勾選當下這一位」，之後切換選手不會跟著換；\
                     要改鎖別人請取消再重新勾。\n\
                     ⚠ 記憶體修改不進存檔，讀過存檔後物件會整批搬家 —— \
                     那時要重新掃描並重新勾一次。")
                .changed();
            if changed {
                self.cheats.lock_player.store(on, Ordering::Relaxed);
                if let Ok(mut g) = self.cheats.lock.lock() {
                    *g = if on { Some(LockTarget::of(&cur)) } else { None };
                }
                self.cheats.lock_stale.store(false, Ordering::Relaxed);
            }
            if on {
                let mut bb = self.cheats.lock_balls.load(Ordering::Relaxed);
                if ui
                    .checkbox(&mut bb, "連球種一起鎖")
                    .on_hover_text(
                        "預設不鎖球種 —— 否則你在遊戲內學到的新球種也會被蓋掉。\n\
                         球種也被結算改掉時才勾。")
                    .changed()
                {
                    self.cheats.lock_balls.store(bb, Ordering::Relaxed);
                }
                // 只有「目前選中的就是鎖定目標」時才同步，
                // 否則切去看別人時會把鎖定目標搶走。
                let mut locked_name = None;
                if let Ok(mut g) = self.cheats.lock.lock() {
                    match g.as_ref() {
                        Some(t) if t.addr == obj => *g = Some(LockTarget::of(&cur)),
                        Some(t) => locked_name = Some(t.name.clone()),
                        None => *g = Some(LockTarget::of(&cur)),
                    }
                }
                if let Some(nm) = locked_name {
                    ui.colored_label(
                        egui::Color32::from_rgb(240, 170, 60),
                        format!("⚠ 目前鎖定的是「{nm}」，不是這一位"));
                } else if self.cheats.lock_stale.load(Ordering::Relaxed) {
                    ui.colored_label(
                        egui::Color32::from_rgb(230, 100, 100),
                        "⚠ 位址已失效（讀過存檔？）—— 請重新掃描後再勾一次");
                } else {
                    let t = self.cheats.ticks.load(Ordering::Relaxed);
                    ui.colored_label(
                        egui::Color32::from_rgb(80, 200, 120),
                        format!("鎖定中（已 {t} 輪）"));
                }
            }
        });
        ui.separator();

        // ── 能力研究：記錄同一位選手「學技能前 / 學技能後」的物件記憶體並做 byte/bit 差分。
        egui::CollapsingHeader::new("🔬 能力研究／記憶體差分")
            .default_open(self.mode == Mode::Koshien)
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(
                        "用法：先按①記錄目前狀態 → 回遊戲只讓這位選手取得一個目標能力 →\n\
                         回來按②比較。修改器會列出物件內所有改變的 offset / byte / bit。"
                    )
                    .small(),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.label("掃描範圍");
                    egui::ComboBox::from_id_source("research_len")
                        .selected_text(format!("+0x0000 ～ +0x{:04X}", self.research_len))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.research_len,
                                PLAYER_READ,
                                format!("已知選手物件 0x{PLAYER_READ:X}"),
                            );
                            ui.selectable_value(
                                &mut self.research_len,
                                0x2000,
                                "擴充 0x2000（建議）",
                            );
                            ui.selectable_value(
                                &mut self.research_len,
                                0x4000,
                                "擴充 0x4000（較多雜訊）",
                            );
                        });
                    ui.checkbox(
                        &mut self.research_single_bit_only,
                        "結果只顯示單一 bit 變化",
                    )
                    .on_hover_text(
                        "找旗標型能力時最有用。完整差分仍保留，可取消勾選查看全部。",
                    );
                });
                ui.horizontal_wrapped(|ui| {
                    if ui.button("① 記錄修改前").clicked() {
                        self.research_capture_before();
                    }
                    let can_compare = self.research_before.is_some();
                    if ui
                        .add_enabled(can_compare, egui::Button::new("② 記錄修改後並比較"))
                        .clicked()
                    {
                        self.research_compare_after();
                    }
                    if ui
                        .add_enabled(can_compare, egui::Button::new("匯出快照 / 差分"))
                        .clicked()
                    {
                        self.research_export();
                    }
                    if ui
                        .add_enabled(can_compare, egui::Button::new("清除研究資料"))
                        .clicked()
                    {
                        self.research_before = None;
                        self.research_diffs.clear();
                        self.status = "能力研究資料已清除".into();
                    }
                });

                if let Some(snap) = self.research_before.as_ref() {
                    let same = snap.addr == obj && snap.name == cur.name;
                    ui.label(
                        egui::RichText::new(format!(
                            "修改前快照：{}　物件 {:#x}　{} bytes{}",
                            snap.name,
                            snap.addr,
                            snap.data.len(),
                            if same { "" } else { "　⚠ 目前選手不同" }
                        ))
                        .small()
                        .color(if same {
                            egui::Color32::from_rgb(80, 200, 120)
                        } else {
                            egui::Color32::from_rgb(240, 170, 60)
                        }),
                    );
                }

                ui.separator();
                ui.label(egui::RichText::new("任意 Offset 讀寫（研究用）").strong());
                ui.label(
                    egui::RichText::new(
                        "相對於目前選手物件讀寫 1 byte。適合驗證差分找到的欄位，例如 +0x002D。\n\
                         ⚠ 寫錯 offset / 數值可能造成遊戲異常；先載入確認，再一次只改一個 byte。"
                    )
                    .small()
                    .weak(),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.label("Offset");
                    ui.add_sized(
                        [90.0, 22.0],
                        egui::TextEdit::singleline(&mut self.research_offset_text)
                            .hint_text("0x002D")
                            .font(egui::TextStyle::Monospace),
                    );
                    if ui.button("載入").clicked() {
                        self.research_load_byte();
                    }
                    ui.label("Value (hex)");
                    ui.add_sized(
                        [54.0, 22.0],
                        egui::TextEdit::singleline(&mut self.research_value_text)
                            .hint_text("00")
                            .font(egui::TextStyle::Monospace),
                    );
                    let loaded_here = self
                        .research_loaded_byte
                        .is_some_and(|(a, _, _)| a == obj);
                    if ui
                        .add_enabled(loaded_here, egui::Button::new("寫入 1 byte"))
                        .on_hover_text("只寫入這個 offset 的 1 byte；切換選手或修改 offset 後必須重新載入。")
                        .clicked()
                    {
                        self.research_write_byte();
                    }
                    if let Some((a, off, v)) = self.research_loaded_byte {
                        if a == obj {
                            ui.monospace(format!("已載入 +0x{off:04X} = {v:02X}"));
                        } else {
                            ui.weak("已切換選手，請重新載入");
                        }
                    }
                });

                if !self.research_diffs.is_empty() {
                    let shown = self
                        .research_diffs
                        .iter()
                        .filter(|d| {
                            !self.research_single_bit_only || d.xor.count_ones() == 1
                        })
                        .count();
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!(
                            "差分 {} 個 byte；目前顯示 {} 個",
                            self.research_diffs.len(),
                            shown
                        ))
                        .strong(),
                    );
                    egui::ScrollArea::vertical()
                        .max_height(260.0)
                        .show(ui, |ui| {
                            egui::Grid::new("research_diff_grid")
                                .num_columns(6)
                                .striped(true)
                                .spacing([10.0, 3.0])
                                .show(ui, |ui| {
                                    ui.strong("Offset");
                                    ui.strong("修改前");
                                    ui.strong("修改後");
                                    ui.strong("XOR");
                                    ui.strong("bit");
                                    ui.strong("備註");
                                    ui.end_row();
                                    for d in &self.research_diffs {
                                        if self.research_single_bit_only
                                            && d.xor.count_ones() != 1
                                        {
                                            continue;
                                        }
                                        let bits = if d.xor.count_ones() == 1 {
                                            format!("bit{}", d.xor.trailing_zeros())
                                        } else {
                                            let mut v = Vec::new();
                                            for b in 0..8 {
                                                if d.xor >> b & 1 == 1 {
                                                    v.push(format!("{b}"));
                                                }
                                            }
                                            format!("bits {}", v.join(","))
                                        };
                                        let note = if (OFF_ABIL2..OFF_ABIL2 + ABIL_BYTES)
                                            .contains(&d.off)
                                        {
                                            "既有特殊能力區"
                                        } else if d.off == OFF_POS || d.off == OFF_POS + 1 {
                                            "主要守位欄位"
                                        } else {
                                            ""
                                        };
                                        ui.monospace(format!("+0x{:04X}", d.off));
                                        ui.monospace(format!("{:02X}", d.before));
                                        ui.monospace(format!("{:02X}", d.after));
                                        ui.monospace(format!("{:02X}", d.xor));
                                        ui.monospace(bits);
                                        if note.is_empty() {
                                            ui.label("");
                                        } else {
                                            ui.weak(note);
                                        }
                                        ui.end_row();
                                    }
                                });
                        });
                    ui.label(
                        egui::RichText::new(
                            "判讀建議：同一能力換 2～3 位選手重複實驗；固定出現的相同 offset/bit 才值得認定。",
                        )
                        .small()
                        .weak(),
                    );
                }
            });
        ui.separator();

        // ── 成長經驗值（★ 明星選手模式的能力值真正來源）
        // 只有找得到經驗值結構時才顯示 —— 栄冠模式沒有這東西
        let growth = self.growth_base.filter(|_| self.cur.as_ref().is_some_and(|c| c.addr == obj));
        if let Some(gb) = growth {
            egui::CollapsingHeader::new("★ 成長經驗值（明星選手要改這裡）")
                .default_open(true)
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(
                            "明星選手模式的能力值是「由累積經驗值算出來的衍生值」。\n\
                             直接拉下面的能力滑桿, 打完比賽或推進日期就會被結算重算回去\
                             （畫面還會顯示「力量已下降 N 了！」）。\n\
                             灌經驗值走的是遊戲自己的成長管線 —— 結算會算出 99 而不是改回去, \
                             報告畫面顯示的是「上升」。",
                        )
                        .small()
                        .weak(),
                    );
                    let exp = self.proc.as_ref().map(|p| growth_exp(p, gb)).unwrap_or_default();
                    egui::Grid::new("growth").num_columns(4).spacing([14.0, 3.0]).show(ui, |ui| {
                        for (i, v) in exp.iter().enumerate() {
                            let full = *v >= GROWTH_EXP_MAX;
                            // 附上換算後的能力值, 才看得懂這個經驗值代表什麼
                            let t = if i == EXP_IDX_SPEED {
                                format!("{}　{}", GROWTH_EXP_NAMES[i], v) // 球速走另一套換算
                            } else {
                                format!("{}　{} → {}", GROWTH_EXP_NAMES[i], v, stat_for_exp(*v))
                            };
                            if full {
                                ui.colored_label(egui::Color32::from_rgb(80, 200, 120), t);
                            } else {
                                ui.label(t);
                            }
                            if i % 4 == 3 {
                                ui.end_row();
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("目標能力值");
                        ui.add(egui::Slider::new(&mut self.growth_target, 0..=99));
                        let e = exp_for_stat(self.growth_target);
                        ui.label(
                            egui::RichText::new(format!("＝ 經驗值 {e}（回推 {}）",
                                                        stat_for_exp(e)))
                                .small().weak(),
                        );
                        if ui
                            .button("套用")
                            .on_hover_text(
                                "把 8 項能力／投手適性／8 個野手守位的經驗值\
                                 都設成「剛好算出這個能力值」的量。\n\
                                 公式 exp = 門檻[L] + (目標 − 基礎[L]) * 分母[L],\
                                 由 exe+62A7A30 反解得出。\n\
                                 ⚠ 球速/耐力那格走另一套換算, 一律灌到上限（→175km/h）。",
                            )
                            .clicked()
                        {
                            let t = self.growth_target;
                            let ok = self.proc.as_ref()
                                .is_some_and(|p| set_growth_target(p, gb, t));
                            act = Some((ok, format!("成長經驗值 → 目標 {t}")));
                        }
                    });
                    if ui
                        .button(format!("★ 全部灌到 {GROWTH_EXP_MAX} → 下次結算後能力全 99"))
                        .on_hover_text(
                            "寫進 10 格經驗值。⚠ 要「打一場比賽或推進日期」讓結算跑過, \
                             能力值才會變 —— 光切換畫面不會重算。\n\
                             實測結果: 球速 159→175km/h、耐力 75→99、其餘 7 項與投手守備適性全 99。\n\
                             ⚠ 記憶體修改不進存檔, 重開遊戲要重來一次。",
                        )
                        .clicked()
                    {
                        let ok = self
                            .proc
                            .as_ref()
                            .is_some_and(|p| set_growth_exp(p, gb, GROWTH_EXP_MAX));
                        act = Some((ok, "成長經驗值（推進一天後能力才會變）".into()));
                    }
                    if ui
                        .button("＋ 連球種數值與各守位適性一起拉")
                        .on_hover_text(
                            "8 個野手守位一律灌滿（+0x68+i*4 → 72600）—— 不灌的話, \
                             你在遊戲內練哪個守位, 哪個就會被算回 G。\n\
                             球種的球威/控球/變化幅度也走同一套經驗值。\n\
                             ⚠ 只提升「本來就非零」的格 —— 值為 0 代表**該項目不存在**\
                             （沒學會的球種、不能守的守位）, 灌下去遊戲會當掉。\n\
                             所以新學一顆球之後要先讓它出現非零經驗值, 這個按鈕才拉得動它。",
                        )
                        .clicked()
                    {
                        let (f, n) = self
                            .proc
                            .as_ref()
                            .map(|p| (set_field_exp(p, gb), raise_growth_extra(p, gb)))
                            .unwrap_or((false, 0));
                        act = Some((
                            f || n > 0,
                            format!("守位經驗值 {}／球種經驗值 {n} 格",
                                    if f { "8 格" } else { "失敗" }),
                        ));
                    }
                    if ui
                        .button("⚡ 立即套用結果（不用等練習）")
                        .on_hover_text(
                            "把「經驗值滿了之後會算出來的結果」直接寫進選手物件：\n\
                             8 項能力 99、球速 175、耐力 99、守備適性全 99。\n\
                             這樣不必等結算跑過就看得到 —— 球種當初能「連練習都不用」\
                             就是因為同時寫了顯示值與經驗值, 這裡把能力值也補上同一半。\n\
                             ⚠ 要先按上面的按鈕灌經驗值, 否則下次結算又會被算回原值。",
                        )
                        .clicked()
                    {
                        let ok = self.proc.as_ref().is_some_and(|p| apply_growth_result(p, obj));
                        act = Some((ok, "立即套用（能力 99／球速 175／耐力 99）".into()));
                    }
                    ui.label(
                        egui::RichText::new(format!(
                            "結構 {gb:#x}　＝　選手物件 +0x{GROWTH_FROM_PLAYER:X}",
                        ))
                        .small()
                        .weak(),
                    );
                });
            ui.separator();
        }

        // ── 個人特質（栄冠專用）
        if self.mode == Mode::Koshien {
            egui::CollapsingHeader::new("個人特質").default_open(true).show(ui, |ui| {
                egui::Grid::new("personal_traits").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                    // 信賴度：u8，遊戲有效上限 0xC8 = 200。
                    ui.label("信賴度").on_hover_text("Player Object +0xE80 / u8 / 0～200");
                    ui.horizontal(|ui| {
                        let mut v = cur.trust.min(200);
                        let slider_changed = ui.add(egui::Slider::new(&mut v, 0..=200).show_value(false)).changed();
                        let input_changed = ui.add(egui::DragValue::new(&mut v).range(0..=200).speed(1.0)).changed();
                        if slider_changed || input_changed {
                            cur.trust = v.min(200);
                            let ok = P!().write(obj + OFF_TRUST, &[cur.trust]);
                            act = Some((ok, format!("信賴度 → {}", cur.trust)));
                        }
                    });
                    ui.end_row();

                    const PERSONALITY_NAMES: [&str; 8] = [
                        "非常普通", "調皮型", "熱血男兒", "冷靜型",
                        "內向", "天才", "人來瘋", "精明幹練",
                    ];
                    ui.label("性格");
                    let old = cur.personality;
                    let shown = PERSONALITY_NAMES.get(cur.personality as usize).copied().unwrap_or("未知");
                    egui::ComboBox::from_id_source(("personality", obj))
                        .selected_text(shown).width(110.0).show_ui(ui, |ui| {
                            for (v, name) in PERSONALITY_NAMES.iter().enumerate() {
                                ui.selectable_value(&mut cur.personality, v as u8, *name);
                            }
                        });
                    if cur.personality != old {
                        let ok = P!().write(obj + OFF_PERSONALITY, &[cur.personality]);
                        act = Some((ok, format!("性格 → {}", PERSONALITY_NAMES[cur.personality as usize])));
                    }
                    ui.end_row();

                    const MOOD_NAMES: [&str; 4] = ["超興奮", "興奮", "普通", "消沉"];
                    ui.label("情緒");
                    let old = cur.mood;
                    let shown = MOOD_NAMES.get(cur.mood as usize).copied().unwrap_or("未知");
                    egui::ComboBox::from_id_source(("mood", obj))
                        .selected_text(shown).width(110.0).show_ui(ui, |ui| {
                            for (v, name) in MOOD_NAMES.iter().enumerate() {
                                ui.selectable_value(&mut cur.mood, v as u8, *name);
                            }
                        });
                    if cur.mood != old {
                        let ok = P!().write(obj + OFF_MOOD, &[cur.mood]);
                        act = Some((ok, format!("情緒 → {}", MOOD_NAMES[cur.mood as usize])));
                    }
                    ui.end_row();

                    // 體力：u16 little-endian，遊戲有效上限 0x01F4 = 500。
                    ui.label("體力").on_hover_text("Player Object +0xE86 / u16 / 0～500（0x0000～0x01F4）");
                    ui.horizontal(|ui| {
                        let mut v = cur.energy.min(500);
                        let slider_changed = ui.add(egui::Slider::new(&mut v, 0..=500).show_value(false)).changed();
                        let input_changed = ui.add(egui::DragValue::new(&mut v).range(0..=500).speed(1.0)).changed();
                        if slider_changed || input_changed {
                            cur.energy = v.min(500);
                            let ok = P!().write(obj + OFF_ENERGY, &cur.energy.to_le_bytes());
                            act = Some((ok, format!("體力 → {}", cur.energy)));
                        }
                    });
                    ui.end_row();

                    // 學力：+0xE88 / u8。2026-08-30 以正確 Player Object 重新驗證有效。
                    // 已確認區間：E=00..23, D=24..2D, C=2E..37, B=38..41, A=42..4B。
                    // 下拉選擇 Rank 時寫入該 Rank 的已知最高值，保留明確且可重現的結果。
                    const ACADEMIC_OPTS: [(u8, &str); 5] = [
                        (0x23, "E"),
                        (0x2D, "D"),
                        (0x37, "C"),
                        (0x41, "B"),
                        (0x4B, "A"),
                    ];
                    let old_academic = cur.academic;
                    let academic_rank = match cur.academic {
                        0x00..=0x23 => Some("E"),
                        0x24..=0x2D => Some("D"),
                        0x2E..=0x37 => Some("C"),
                        0x38..=0x41 => Some("B"),
                        0x42..=0x4B => Some("A"),
                        _ => None,
                    };
                    ui.label("學力").on_hover_text(format!(
                        "Player Object +0xE88 / u8\n已確認區間：E=00～23, D=24～2D, C=2E～37, B=38～41, A=42～4B\n目前 raw：0x{:02X}",
                        cur.academic
                    ));
                    let shown = academic_rank
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("未知 (0x{:02X})", cur.academic));
                    egui::ComboBox::from_id_source(("academic", obj))
                        .selected_text(shown)
                        .width(110.0)
                        .show_ui(ui, |ui| {
                            for &(raw, rank) in &ACADEMIC_OPTS {
                                if ui.selectable_label(academic_rank == Some(rank), rank).clicked() {
                                    cur.academic = raw;
                                    ui.close_menu();
                                }
                            }
                        });
                    if cur.academic != old_academic {
                        let rank = match cur.academic {
                            0x23 => "E",
                            0x2D => "D",
                            0x37 => "C",
                            0x41 => "B",
                            0x4B => "A",
                            _ => "?",
                        };
                        let ok = P!().write(obj + OFF_ACADEMIC, &[cur.academic]);
                        act = Some((ok, format!("學力 → {rank} (0x{:02X})", cur.academic)));
                    }
                    ui.end_row();

                    // 招募評價：u16，0..=0x01FF；星數只是遊戲 UI 的區間顯示。
                    let stars = match cur.recruit_eval.min(0x01FF) {
                        0x0000..=0x0027 => 1,
                        0x0028..=0x004F => 2,
                        0x0050..=0x009F => 3,
                        0x00A0..=0x00EF => 4,
                        _ => 5,
                    };
                    ui.label("招募評價").on_hover_text(format!(
                        "Player Object +0xE8C / u16 / 0～511（0x0000～0x01FF）\n目前：{}★",
                        stars
                    ));
                    ui.horizontal(|ui| {
                        let mut v = cur.recruit_eval.min(511);
                        let slider_changed = ui.add(egui::Slider::new(&mut v, 0..=511).show_value(false)).changed();
                        let input_changed = ui.add(egui::DragValue::new(&mut v).range(0..=511).speed(1.0)).changed();
                        ui.label("★".repeat(stars));
                        if slider_changed || input_changed {
                            cur.recruit_eval = v.min(511);
                            let ok = P!().write(obj + OFF_RECRUIT_EVAL, &cur.recruit_eval.to_le_bytes());
                            act = Some((ok, format!("招募評價 → {}", cur.recruit_eval)));
                        }
                    });
                    ui.end_row();
                });
            });
            ui.separator();
        }

        // ── 基本
        egui::CollapsingHeader::new("基本").default_open(true).show(ui, |ui| {
            egui::Grid::new("basic").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label("球速 km/h")
                    .on_hover_text("球速有自己的換算表（基礎158/門檻結構+0x158/分母9000…）,\n\
                                    拉滑桿會同步寫經驗值, 練習不會回退。\n\
                                    ⚠ 上限就是遊戲的 175 —— 實測 patch 掉程式碼上限後\n\
                                    　 資料上顯示 207, 但實戰投出來仍然是 175, 沒有意義。");
                if ui.add(egui::Slider::new(&mut cur.speed, 80..=SPEED_UI_MAX)).changed() {
                    let ok = write_pack_synced(P!(), obj, cur.speed, cur.stamina, cur.pack_hi);
                    act = Some((ok, "球速（含經驗值）".into()));
                }
                ui.end_row();

                ui.label("耐力")
                    .on_hover_text("耐力有自己的經驗值格（+0x60）, 跟能力值同一組換算表,\n\
                                    所以拉這個滑桿**會**同步寫經驗值, 練習不會回退。");
                if ui.add(egui::Slider::new(&mut cur.stamina, 0..=99)).changed() {
                    let ok = write_pack_synced(P!(), obj, cur.speed, cur.stamina, cur.pack_hi);
                    act = Some((ok, "耐力（含經驗值）".into()));
                }
                ui.end_row();

                ui.label("投手適性");
                if ui.add(egui::Slider::new(&mut cur.defense, 0..=99)).changed() {
                    let ok = write_def_synced(P!(), obj, cur.defense);
                    act = Some((ok, "投手適性（含經驗值）".into()));
                }
                ui.end_row();

                // 栄冠：主要守備位置（+0xA30 bit3~6）。
                // 只改「主要位置」本身，不會自動改下方各守位適性。
                if self.mode == Mode::Koshien {
                    ui.label("主要守備位置")
                        .on_hover_text("栄冠部員一覽與選手標題使用的主要守備位置。\n\
                                        存在 +0xA30 的 bit3~6；寫入時會保留同一 u16 的其他旗標。\n\
                                        ※ 只改主要位置，不會自動提高該守位適性；需要時請再調整下方守位適性。");
                    let old_pos = cur.pos;
                    egui::ComboBox::from_id_source(("main_pos", obj))
                        .selected_text(pos_name(cur.pos))
                        .width(90.0)
                        .show_ui(ui, |ui| {
                            for (v, name) in POS_NAMES.iter().enumerate() {
                                ui.selectable_value(&mut cur.pos, v as u8, *name);
                            }
                        });
                    if cur.pos != old_pos {
                        let ok = write_pos(P!(), obj, cur.pos);
                        if ok {
                            // 左側清單是 self.list 的快照；同步更新，讓位置圖示與分組立即一致。
                            if let Some(i) = self.sel {
                                if let Some(pl) = self.list.get_mut(i) {
                                    pl.pos = cur.pos;
                                }
                            }
                        }
                        act = Some((ok, format!("主要守備位置 → {}", pos_name(cur.pos))));
                    }
                    ui.end_row();
                }

                // 栄冠：打擊姿勢。三欄聯合編碼（+0x2C bit7 / +0x2D low2 / +0xFB6 low3）。
                // 只在栄冠顯示：目前映射只在栄冠球員上完成交叉驗證。
                if self.mode == Mode::Koshien {
                    ui.label("打擊姿勢")
                        .on_hover_text("已實測的 7 種打球型態。選擇後會同步修改：\n\
                                        +0x2C bit7、+0x2D low2、+0xFB6 low3。\n\
                                        每一處都只改已確認的 bits，其他旗標（包含捕手配球）會保留。");
                    let old_style = cur.batting_style;
                    egui::ComboBox::from_id_source(("batting_style", obj))
                        .selected_text(batting_style_name(cur.batting_style))
                        .width(130.0)
                        .show_ui(ui, |ui| {
                            for (v, name) in BATTING_STYLE_NAMES.iter().enumerate() {
                                ui.selectable_value(&mut cur.batting_style, v as u8, *name);
                            }
                        });
                    if cur.batting_style != old_style && cur.batting_style != BATTING_STYLE_UNKNOWN {
                        let ok = write_batting_style(P!(), obj, cur.batting_style);
                        act = Some((ok, format!("打擊姿勢 → {}", batting_style_name(cur.batting_style))));
                    }
                    ui.end_row();
                }

                // 8 個野手守位（+0x18..0x1F）。⚠ 只寫顯示值撐不住 ——
                // 沒練的守位看起來正常, 一旦在遊戲內練它就會依經驗值被算回 G,
                // 所以這裡走 write_field_synced（顯示值＋經驗值一起寫）。
                for fi in 0..GROWTH_FIELD_N {
                    ui.label(FIELD_NAMES[fi]);
                    if ui.add(egui::Slider::new(&mut cur.field[fi], 0..=99)).changed() {
                        let ok = write_field_synced(P!(), obj, fi, cur.field[fi]);
                        act = Some((ok, format!("{}（含經驗值）", FIELD_NAMES[fi])));
                    }
                    ui.end_row();
                }

                // 捕手配球（+0x2C bit4~6）。捕手以外的選手一律 G，遊戲也不顯示。
                ui.label("捕手配球")
                    .on_hover_text("畫面右下角那個 G~S。存在 +0x2C 的 bit4~6，\n\
                                    同一 byte 還有別的旗標, 所以是讀-改-寫。\n\
                                    捕手以外的選手遊戲不顯示這一項。");
                if let Some(g) = grade_btn(ui, cur.catcher, &GS_OPTS, 52.0) {
                    cur.catcher = g;
                    let ok = write_catcher(P!(), obj, g);
                    act = Some((ok, "捕手配球".into()));
                }
                ui.end_row();

                ui.label("年級（栄冠）");
                if ui.add(egui::Slider::new(&mut cur.grade, 1..=3)).changed() {
                    let ok = P!().write(obj + OFF_GRADE, &[cur.grade]);
                    act = Some((ok, "年級".into()));
                }
                ui.end_row();

                ui.label("球棒道具已用 / 上限1");
                if ui.add(egui::Slider::new(&mut cur.item, 0..=9)).changed() {
                    let ok = P!().write(obj + OFF_ITEM, &[cur.item]);
                    act = Some((ok, "球棒使用次數".into()));
                }
                ui.end_row();

                ui.label("書籍已用 / 上限依學歷");
                if ui.add(egui::Slider::new(&mut cur.book, 0..=9)).changed() {
                    let ok = P!().write(obj + OFF_BOOK, &[cur.book]);
                    act = Some((ok, "書籍使用次數".into()));
                }
                ui.end_row();

            });
            if ui.button("道具/書籍使用次數歸零（＝無限使用）").clicked() {
                cur.item = 0;
                cur.book = 0;
                let ok = P!().write(obj + OFF_ITEM, &[0, 0]);
                act = Some((ok, "使用次數歸零".into()));
            }
        });

        // ── 擅長・不擅長球路（九宮格）
        egui::CollapsingHeader::new("擅長・不擅長球路（九宮格）")
            .default_open(true)
            .show(ui, |ui| {
                ui.label("排法跟遊戲畫面一樣（左上→右下）。左鍵 +1，超過 +3 繞回 −3；右鍵直接選。")
                    .on_hover_text("+0xA50 起 9 個 3-bit 欄位, 3-bit 二補數編碼。\n\
                                    27 bits 用掉、高 5 bits 是別的東西, 所以整個 u32 讀-改-寫。");
                let mut changed = false;
                egui::Grid::new("zone").num_columns(3).spacing([4.0, 4.0]).show(ui, |ui| {
                    for r in 0..3 {
                        for c in 0..3 {
                            let i = r * 3 + c;
                            if let Some(nv) = zone_btn(ui, cur.zone[i]) {
                                cur.zone[i] = nv;
                                changed = true;
                            }
                        }
                        ui.end_row();
                    }
                });
                if changed {
                    let ok = write_zone(P!(), obj, &cur.zone);
                    act = Some((ok, "擅長球路九宮格".into()));
                }
                if ui.button("全部歸零").clicked() {
                    cur.zone = [0; ZONE_N];
                    let ok = write_zone(P!(), obj, &cur.zone);
                    act = Some((ok, "擅長球路九宮格（歸零）".into()));
                }
            });

        // ── 能力值
        egui::CollapsingHeader::new("能力值").default_open(true).show(ui, |ui| {
            egui::Grid::new("stats").num_columns(3).spacing([12.0, 6.0]).show(ui, |ui| {
                for i in 0..8 {
                    ui.label(STAT_NAMES[i]);
                    let mut v = cur.stats[i];
                    // 上限 99 —— 遊戲自己的換算就夾在 99（exe+62A7A30 的 min(…, 0x63)），
                    // 拉到 127 只是寫個遊戲不承認的值
                    if ui.add(egui::Slider::new(&mut v, 1..=STAT_UI_MAX)).changed() {
                        cur.stats[i] = v;
                        let ok = write_stat_synced(P!(), obj, i, v);
                        act = Some((ok, STAT_NAMES[i].into()));
                    }
                    ui.label(grade_of(cur.stats[i]));
                    ui.end_row();
                }
            });
        });

        // ── 特殊能力（+0x08..0x15 的 28 個 nibble）
        egui::CollapsingHeader::new("特殊能力").default_open(true).show(ui, |ui| {
            // 等級格：低 3 bit ＝ 以 D 為 0 的 signed 等級，bit3 ＝ 另一個獨立能力。
            // ⚠ 值 4（＝−4）超出等級表，實測必崩 —— 所以下拉選單裡根本不提供。
            ui.label(egui::RichText::new("等級能力（選單裡沒有會當機的值，可以放心拉）").strong());
            // ★ 明星選手模式專用：等級與 bit3 附加能力擠在同一個 nibble，
            //   遊戲升級時整個 nibble 重寫 → 同格的 bit3 會被洗掉（＝「學新技能後被重置」）。
            //   拉到最高就不會再升級, bit3 也就保得住。
            if growth.is_some() {
                if ui
                    .button("★ 等級全部拉到最高（保留附加能力）")
                    .on_hover_text(
                        "把 11 個等級格拉到「觀察過的最高等級」, 並保留各格的 bit3 附加能力。\n\
                         為什麼要這樣: 等級(低3bit)與 bit3 擠在同一個 nibble, \
                         遊戲升級時是整個 nibble 重寫 —— 所以每升一級就會把同格的\
                         附加能力洗掉。拉到最高就不會再升級。\n\
                         ⚠ 逐格從 A 往下找「1491 位真實選手身上出現過」的值, \
                         不會寫出沒觀察過的組合（那會讓遊戲當掉）。\n\
                         ⚠ 犀利度／尾勁本來就沒有的話不會無中生有。")
                    .clicked()
                {
                    let n = self.proc.as_ref().and_then(|p| max_abil_grades(p, obj));
                    act = Some((n.is_some(), match n {
                        Some(k) => format!("等級拉滿（改了 {k} 格，附加能力保留）"),
                        None => "等級拉滿失敗".into(),
                    }));
                    need_reload = true;
                }
                ui.label(
                    egui::RichText::new(
                        "明星選手：特殊能力**不走經驗值**, 直接改就會留住（已實測）。\
                         但等級升級會洗掉同格的附加能力, 所以建議先按上面那顆。")
                        .small().weak(),
                );
            }
            egui::Grid::new("abil_graded").num_columns(3).spacing([10.0, 4.0]).show(ui, |ui| {
                for &n in ABIL_GRADED {
                    let optional = ABIL_GRADED_OPTIONAL.contains(&n);
                    let nib = abil_nib(&cur.abil, n);
                    let (lv, extra) = (nib & 7, nib & 8 != 0);

                    ui.label(abil_name(n));

                    // 低→高排列（grade_btn 要的順序）。
                    // ⚠ 值 4（＝signed −4）超出等級表, 實測必崩 —— 所以清單裡根本沒有它,
                    //   點擊循環也就不可能踩到。
                    // ⚠ 選配型（犀利度／尾勁）的 0 是「沒有這個能力」而不是 D。
                    let mut opts: Vec<(u8, &str)> =
                        vec![(5, "G"), (6, "F"), (7, "E"), (0, "D"), (1, "C"), (2, "B"), (3, "A")];
                    if optional {
                        opts.retain(|&(v, _)| v != 0);
                        opts.insert(0, (0, "（無）"));
                    }
                    if let Some(newlv) = grade_btn(ui, lv, &opts, 78.0) {
                        let nv = (nib & 8) | newlv;
                        let ok = write_abil_nibble(P!(), obj, n, nv);
                        set_nib(&mut cur.abil, n, nv);
                        act = Some((ok, format!("{} 等級", abil_name(n))));
                    }

                    let bit3 = ABIL_GRADED_BIT3.iter().find(|e| e.0 == n).map(|e| e.1).unwrap_or("");
                    let mut on = extra;
                    if !bit3.is_empty() && ui.checkbox(&mut on, bit3).changed() {
                        let nv = (nib & 7) | if on { 8 } else { 0 };
                        let ok = write_abil_nibble(P!(), obj, n, nv);
                        set_nib(&mut cur.abil, n, nv);
                        act = Some((ok, bit3.into()));
                    }
                    ui.end_row();
                }
            });

            // ── 野手風格：已實測確認「打擊積極性／選球眼」G~A，以及「人氣」旗標。
            // 顯示方式沿用捕手配球的 grade_btn：左鍵升一級，右鍵直接選。
            if self.mode == Mode::Koshien {
                ui.add_space(6.0);
                ui.separator();
                ui.label(egui::RichText::new("野手風格").strong());
                egui::Grid::new("fielder_style").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
                    const FIELDER_GRADE_OPTS: [(u8, &str); 7] = [
                        (0, "G"), (1, "F"), (2, "E"), (3, "D"),
                        (4, "C"), (5, "B"), (6, "A"),
                    ];

                    ui.label("打擊積極性")
                        .on_hover_text(
                            "栄冠模式實測：G~A（沒有 S）。\n\
                             顯示等級在 +0xA5B low3，同步值在 +0x10AE low3；\n\
                             修改時會同步寫兩處，其他 bits 原樣保留。"
                        );
                    if let Some(g) = grade_btn(ui, cur.batting_aggression, &FIELDER_GRADE_OPTS, 52.0) {
                        cur.batting_aggression = g;
                        let ok = write_batting_aggression(P!(), obj, g);
                        act = Some((ok, format!("打擊積極性 → {}", FIELDER_GRADE_OPTS[g as usize].1)));
                    }
                    ui.end_row();

                    ui.label("選球眼")
                        .on_hover_text(
                            "栄冠模式實測：G~A（沒有 S）。\n\
                             顯示等級在 +0xA53 bit3~5，同步值在 +0x10AA low3；\n\
                             修改時會同步寫兩處，其他 bits 原樣保留。"
                        );
                    if let Some(g) = grade_btn(ui, cur.plate_discipline, &FIELDER_GRADE_OPTS, 52.0) {
                        cur.plate_discipline = g;
                        let ok = write_plate_discipline(P!(), obj, g);
                        act = Some((ok, format!("選球眼 → {}", FIELDER_GRADE_OPTS[g as usize].1)));
                    }
                    ui.end_row();

                    ui.label("人氣(投手/野手)")
                        .on_hover_text(
                            "栄冠模式實測：+0xA30 low3=1 時沒有人氣，=2 時有人氣。\n\
                             只修改 low3，主要守備位置所在的 bit3~6 會原樣保留。"
                        );
                    let mut popularity = cur.popularity;
                    if ui.checkbox(&mut popularity, "").changed() {
                        cur.popularity = popularity;
                        let ok = write_popularity(P!(), obj, popularity);
                        act = Some((ok, format!("人氣(投手/野手) → {}", if popularity { "有" } else { "無" })));
                    }
                    ui.end_row();
                });
            }

            ui.add_space(6.0);
            ui.separator();
            ui.label(egui::RichText::new("變體能力（一列 ＝ 一個 nibble 的 4 個 bit）").strong());
            ui.label(egui::RichText::new(
                "⚠ 同一列的 bit0/bit1 是一組、bit2/bit3 是一組。同組兩者若是同一能力的\
                 正負或輕重版本，同時勾選時畫面只會畫其中一個（不是沒寫進去）。")
                .weak().small());

            egui::Grid::new("abil_bits").num_columns(5).spacing([8.0, 3.0]).show(ui, |ui| {
                for n in 0..ABIL_NIBBLES {
                    if abil_is_graded(n) {
                        continue;
                    }
                    let nib = abil_nib(&cur.abil, n);
                    ui.label(egui::RichText::new(format!("n{n:<2}")).weak().small());
                    for b in 0..4u8 {
                        let name = ABIL_BITS.iter()
                            .find(|e| e.0 == n && e.1 == b)
                            .map(|e| e.2).unwrap_or("—");
                        let mut on = nib >> b & 1 == 1;
                        if ui.add_enabled(name != "—", egui::Checkbox::new(&mut on, name))
                            .changed()
                        {
                            let nv = if on { nib | 1 << b } else { nib & !(1 << b) };
                            let ok = write_abil_nibble(P!(), obj, n, nv);
                            set_nib(&mut cur.abil, n, nv);
                            // 這個組合值沒在 1491 位真實選手身上出現過 —— 多半沒事，
                            // 但既然有崩潰前例就講清楚，不要讓使用者以為是位址失效。
                            let warn = ABIL_SEEN_VALS[n] >> nv & 1 == 0;
                            act = Some((ok, if warn {
                                format!("{name}　⚠ n{n}={nv} 這個組合沒觀察過，若畫面卡住就重開讀檔")
                            } else {
                                name.into()
                            }));
                        }
                    }
                    ui.end_row();
                }
            });

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("全部清空").clicked() {
                    let ok = P!().write(obj + OFF_ABIL2, &[0u8; ABIL_BYTES]);
                    cur.abil = [0; ABIL_BYTES];
                    act = Some((ok, "特殊能力全部清空".into()));
                }
                ui.label(egui::RichText::new(format!(
                    "現值 {}",
                    cur.abil.iter().map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>().join(" ")))
                    .weak().small().monospace());
            });
        });

        // ── 球種
        egui::CollapsingHeader::new("球種").default_open(true).show(ui, |ui| {
            ui.checkbox(&mut self.cross_dir,
                        "允許跨系統（遊戲不擋，但畫面會出現「直球位置放滑球」這種怪東西）");
            ui.separator();
            // 依官方的 6 系統排列（直球系在前，跟球種 ID 分段一致），
            // 而且同一系的兩顆排在一起 —— slot i 與 slot i+6 是同一系。
            for dir in DIR_ORDER {
                for second in [false, true] {
                    let slot = dir + if second { 6 } else { 0 };
                    let tag = format!("{}・第{}顆", DIR_SERIES[dir], if second { 2 } else { 1 });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!(
                        "{}{}", DIR_SERIES[dir], if second { "・第2顆" } else { "・第1顆" }))
                        .strong());
                    ui.label(egui::RichText::new(format!("{}　slot{slot}", DIR_UI[dir]))
                        .weak().small());
                });
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    let opts: Vec<u8> = if self.cross_dir {
                        let mut v = vec![BALL_EMPTY, BALL_ORIGINAL];
                        v.extend(BALL_NAMES.iter().map(|e| e.0).filter(|&i| i != BALL_ORIGINAL));
                        v
                    } else {
                        balls_for_dir(dir)
                    };
                    let mut id = cur.balls[slot].id;
                    egui::ComboBox::from_id_source(("ball", slot))
                        .width(210.0)
                        .selected_text(cur.ball_label(slot))
                        .show_ui(ui, |ui| {
                            for o in opts {
                                let txt = if o == BALL_ORIGINAL {
                                    "原創球種（下面選要哪一顆）".to_string()
                                } else {
                                    ball_name(o)
                                };
                                ui.selectable_value(&mut id, o, txt);
                            }
                        });
                    if id != cur.balls[slot].id {
                        let was_orig = cur.balls[slot].id == BALL_ORIGINAL;
                        cur.balls[slot].id = id;
                        if id != BALL_EMPTY && cur.balls[slot].power == 0 {
                            cur.balls[slot].power = 7;
                            cur.balls[slot].control = 7;
                            cur.balls[slot].move_ = if dir == 5 { 0 } else { 4 };
                        }
                        let b = cur.balls[slot].clone();
                        // ★ 明星選手：write_ball_synced 會一併寫該 slot 的三格經驗值,
                        //   否則下次結算會依經驗值（新球是 0）把三項算回 G。
                        let mut ok = write_ball_synced(P!(), obj, slot, &b);
                        // 換掉原創球種時把那筆記錄一起清掉, 避免留下孤兒記錄
                        if was_orig && id != BALL_ORIGINAL {
                            if let Some(ri) = cur.recs.iter().position(|r| r.slot == slot as u32) {
                                ok &= clear_rec(P!(), obj, ri);
                            }
                        }
                        need_reload = true;
                        act = Some((ok, format!("{tag} 球種")));
                    }

                    if cur.balls[slot].id != BALL_EMPTY {
                        let mut changed = false;
                        ui.label("球威");
                        if let Some(n) = grade_btn(ui, cur.balls[slot].power, &GS_OPTS, 46.0) {
                            cur.balls[slot].power = n;
                            changed = true;
                        }
                        ui.label("控球");
                        if let Some(n) = grade_btn(ui, cur.balls[slot].control, &GS_OPTS, 46.0) {
                            cur.balls[slot].control = n;
                            changed = true;
                        }
                        if dir != 5 {
                            ui.label("變化量");
                            let mut mv = cur.balls[slot].move_;
                            if ui.add(egui::Slider::new(&mut mv, 0..=7).show_value(true)).changed() {
                                cur.balls[slot].move_ = mv;
                                changed = true;
                            }
                        }
                        if changed {
                            let b = cur.balls[slot].clone();
                            let ok = write_ball_synced(P!(), obj, slot, &b);
                            act = Some((ok, format!("{tag} 球威/控球/變化（含經驗值）")));
                        }
                    }
                });

                // ── 這一格是原創球種 → 直接在這裡挑要哪一顆（每個 slot 各自獨立）
                if cur.balls[slot].id == BALL_ORIGINAL {
                    ui.horizontal(|ui| {
                        ui.add_space(28.0);
                        if self.lib.is_empty() {
                            ui.colored_label(
                                egui::Color32::from_rgb(230, 170, 80),
                                "沒有球種庫 → 畫面只會顯示「原創」。\
                                 按最上面的「⟳ 蒐集原創球種到球種庫」",
                            );
                            return;
                        }
                        let curname = cur
                            .rec_for_slot(slot)
                            .map(|r| r.name.clone())
                            .unwrap_or_default();
                        let opts: Vec<usize> = (0..self.lib.len())
                            .filter(|&i| self.cross_dir || self.lib[i].dir == dir)
                            .collect();
                        let sel_txt = if curname.is_empty() {
                            "（未設定→畫面只顯示「原創」，點這裡挑一顆）".to_string()
                        } else {
                            zh_name(&curname)
                        };
                        let mut pick: Option<usize> = None;
                        ui.label("↳ 原創內容");
                        egui::ComboBox::from_id_source(("orig", slot))
                            .width(330.0)
                            .selected_text(sel_txt)
                            .show_ui(ui, |ui| {
                                for i in opts {
                                    let e = &self.lib[i];
                                    let txt = format!(
                                        "{}　[{}]　基底 {}　{}",
                                        zh_name(&e.name), e.kind, ball_name(e.base), e.holder
                                    );
                                    if ui.selectable_label(e.name == curname, txt).clicked() {
                                        pick = Some(i);
                                    }
                                }
                            });
                        if let Some(i) = pick {
                            let p = match &self.proc { Some(p) => p, None => return };
                            let e = &self.lib[i];
                            let ri = find_rec_index(p, obj, slot);
                            match ri {
                                Some(ri) => {
                                    let ok = write_rec(p, obj, ri, &e.raw, slot);
                                    need_reload = true;
                                    act = Some((ok, format!("{tag} 原創「{}」", e.name)));
                                }
                                None => act = Some((false, "12 筆原創記錄都滿了".into())),
                            }
                        }
                    });
                }
                ui.add_space(2.0);
                } // for second（同一系的第 1／第 2 顆）
                ui.separator();
            } // for dir（6 個球種系統）
            ui.horizontal(|ui| {
                if ui.button("全部球威/控球 → S").clicked() {
                    let p = match &self.proc { Some(p) => p, None => return };
                    let mut ok = true;
                    for s in 0..N_BALL {
                        if cur.balls[s].id != BALL_EMPTY {
                            cur.balls[s].power = 7;
                            cur.balls[s].control = 7;
                            ok &= write_ball(p, obj, s, &cur.balls[s].clone());
                        }
                    }
                    act = Some((ok, "全部球種 S/S".into()));
                }
                if ui.button("變化量全部 → 7（直球系除外）").clicked() {
                    let p = match &self.proc { Some(p) => p, None => return };
                    let mut ok = true;
                    for s in 0..N_BALL {
                        if cur.balls[s].id != BALL_EMPTY && s % 6 != 5 {
                            cur.balls[s].move_ = 7;
                            ok &= write_ball(p, obj, s, &cur.balls[s].clone());
                        }
                    }
                    act = Some((ok, "變化量 7".into()));
                }
            });
        });

        // ── 原創球種：總覽（實際挑選在上面每一格的「↳ 原創內容」）
        //    ⚠ 蒐集按鈕不放這裡 —— 它是對整個球種庫做的事, 跟選中誰無關,
        //      而且這一區要先選到選手才畫得出來。放在頂端工具列。
        egui::CollapsingHeader::new("原創球種 — 目前的記錄").default_open(false).show(ui, |ui| {
            ui.label("球種陣列寫 ID36 只是旗標，名稱與效果來自這些記錄（每位選手最多 12 筆，\
                      一筆對應一個 slot）。要挑哪一顆請在上面「球種」區各格的『↳ 原創內容』選。");
            ui.separator();
            let mut any = false;
            for (i, r) in cur.recs.iter().enumerate() {
                if r.slot >= REC_UNUSED_SLOT && r.name.is_empty() {
                    continue;
                }
                any = true;
                ui.label(format!("　rec#{i}　slot{}（方向{}）　{}　[{}]　基底 {}",
                                 r.slot, r.slot as usize % 6, zh_name(&r.name),
                                 if r.official { "官方" } else { "自訂" },
                                 ball_name(r.base)));
            }
            if !any {
                ui.label("　（無）");
            }
        });

        // cur 是右側編輯快照。不要每幀無條件灌回 self.list；
        // 否則遊戲自然成長後，2 秒同步的新值會被舊 cur 反覆覆蓋。
        self.cur = Some(cur.clone());
        if let Some(i) = switch {
            self.sel = Some(i);
            self.reload_current();
            self.status = format!(
                "已切到第 {} 份副本（物件 {:#x}）—— 改完切換畫面看看這份有沒有生效",
                sibs.iter().position(|&x| x == i).map_or(0, |k| k + 1),
                self.list[i].addr
            );
            return;
        }
        if let Some((ok, what)) = act {
            if what == "（重新讀取）" {
                self.reload_current();
            } else {
                self.write_ok(ok, &what);
                if need_reload {
                    self.reload_current();
                }
            }
        }
    }
}

// 正常關閉修改器時：
// 1. 若本次 UI 仍勾選「招募機率100%」，自動取消並還原兩張招募機率資料表。
// 2. 若遊戲 process 仍存活，將天才出現機率恢復為遊戲原生 1%。
// 不做任何啟動時或無條件的招募機率資料 reset；lib 端只還原本 instance 成功套用且仍符合 patched 值的欄位。
impl Drop for App {
    fn drop(&mut self) {
        if let Some(p) = self.proc.as_ref() {
            if self.recruit_rate_100 {
                let _ = set_recruit_rate_100(p, false);
            }
            let _ = set_talent_rate(p, TALENT_RATE_DEFAULT);
        }
        self.recruit_rate_100 = false;
        self.talent_rate = TALENT_RATE_DEFAULT;
    }
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 800.0])
            .with_min_inner_size([820.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "prospi 選手編輯器",
        opts,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
