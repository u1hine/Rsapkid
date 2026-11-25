
use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use zip::ZipArchive;
use std::collections::HashMap;
use clap::Parser;


#[derive(Debug, Parser)]
#[command(name = "Rsapkid")]
#[command(about = "APK壳扫描工具，支持单文件扫描 / 目录批量扫描")]
#[command(version)]
struct Args {
    /// 单个APK文件路径
    #[arg(conflicts_with = "dir")]
    apk: Option<String>,

    /// 批量扫描目录下所有APK
    #[arg(short, long, conflicts_with = "apk")]
    dir: Option<String>,
}

fn scan_dir(dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext.eq_ignore_ascii_case("apk") {
                    let p = path.to_string_lossy();
                    println!("正在扫描：{}", p);
                    if let Err(e) = scan_apk(&p) {
                        eprintln!("扫描 {} 失败: {}", p, e);
                    }
                }
            }
        }
    }
    Ok(())
}
// 扫描 APK
fn scan_apk(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut archive = ZipArchive::new(file)?;

    let signatures = get_signatures();

    let mut detected = HashSet::new();

    println!("[*] APK 文件数量: {}", archive.len());

    for i in 0..archive.len() {
        let file = archive.by_index(i)?;

        // APK 内部完整路径
        let entry_name = file.name().to_string();

        // 提取文件名
        let file_name = Path::new(&entry_name)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        // 匹配加固特征
        for (signature, protector) in &signatures {
            if file_name.contains(signature) || entry_name.contains(signature) {
                detected.insert((*protector, (*signature).to_string()));

                println!(
                    "[+] 命中加固特征: {} => {}",
                    signature, protector
                );
            }
        }
    }

    println!("\n========== 扫描结果 ==========");

    if detected.is_empty() {
        println!("[-] 未发现已知加固特征");
    } else {
        let vendors: HashSet<_> = detected
            .iter()
            .map(|(vendor, _)| *vendor)
            .collect();

        for vendor in vendors {
            println!("[+] 加固厂商: {}", vendor);
        }

        println!("[+] 命中特征数量: {}", detected.len());
    }

    Ok(())
}

// 特征库：这里复用你之前的 get_signatures()
// 将上一个版本中完整的 HashMap::from([...]) 放到这里
fn get_signatures() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        // 360加固
        ("libjiagu.so", "360加固"),
        ("libjiagu_ls.so", "360加固"),
        ("libjiagu_x86.so", "360加固"),
        ("libjiagu_a64.so", "360加固"),
        ("libjiagu_x64.so", "360加固"),
        ("libjiagu_art.so", "360加固"),
        ("libjgdtc.so", "360加固"),
        ("libjgdtc_x86.so", "360加固"),
        ("libjgdtc_a64.so", "360加固"),
        ("libjgdtc_x64.so", "360加固"),
        ("libjgdtc_art.so", "360加固"),
        ("libprotectClass.so", "360加固"),
        ("libSafeManageService.so", "360加固"),
        (".appkey", "360加固"),

        // APKProtect
        ("libAPKProtect.so", "APKProtect"),

        // apktoolplus
        ("libapktoolplus_jiagu.so", "apktoolplus"),
        ("jiagu_data.bin", "apktoolplus"),
        ("sign.bin", "apktoolplus"),

        // CFCA加固
        ("libbasec.so", "CFCA加固"),
        ("libbasec_x86.so", "CFCA加固"),
        ("libsecenh.so", "CFCA加固"),
        ("libsecenh_a64.so", "CFCA加固"),
        ("libsecenh_x86.so", "CFCA加固"),
        ("my_classes.jar", "CFCA加固"),

        // DexProtect
        ("classes.dex.dat", "DexProtect加固"),
        ("dp.arm-v7.so.dat", "DexProtect加固"),
        ("dp.arm.so.dat", "DexProtect加固"),

        // OPPO
        ("OPPOProtect.so", "OPPO应用加固"),
        ("OPPOProtect2019.so", "OPPO应用加固"),

        // UU安全
        ("libuusafe.jar.so", "UU安全加固"),
        ("libuusafe.so", "UU安全加固"),
        ("libuusafeempty.so", "UU安全加固"),

        // 中国移动加固
        ("libcmvmp.so", "中国移动加固"),
        ("libmogosec_dex.so", "中国移动加固"),
        ("libmogosec_sodecrypt.so", "中国移动加固"),
        ("libmogosecurity.so", "中国移动加固"),
        ("ibmogosecurity.so", "中国移动加固"),
        ("mogosec_classes", "中国移动加固"),
        ("mogosec_data", "中国移动加固"),
        ("mogosec_dexinfo", "中国移动加固"),
        ("mogosec_march", "中国移动加固"),

        // 几维安全
        ("kdpdata.so", "几维安全"),
        ("libkdp.so", "几维安全"),
        ("libkwscmm.so", "几维安全"),
        ("libkwscr.so", "几维安全"),
        ("libkwslinker.so", "几维安全"),
        ("dex.dat", "几维安全"),

        // 启明星辰
        ("libvenSec.so", "启明星辰"),
        ("libvenustech.so", "启明星辰"),

        // 娜迦加固
        ("libchaosvmp.so", "娜迦加固"),
        ("libddog.so", "娜迦加固"),
        ("libfdog.so", "娜迦加固"),
        ("libhdog.so", "娜迦加固"),
        ("libedog.so", "娜迦加固（企业版）"),
        ("libvdog.so", "娜迦加固（开发者试用版-VMP）"),
        ("libvdog-x86.so", "娜迦加固（开发者试用版-VMP）"),
        ("libxloader.so", "娜迦加固（新版2022）"),
        ("fake_classes.dex", "娜迦加固（新版2022）"),

        // 梆梆安全
        ("libDexHelper.so", "梆梆安全（企业版）"),
        ("libDexHelper-x86.so", "梆梆安全（企业版）"),
        ("DexHelper.so", "梆梆安全（定制版）"),
        ("libSecShell.so", "梆梆安全（免费版）"),
        ("libSecShell_art.so", "梆梆安全（免费版）"),
        ("libSecShel1.so", "梆梆安全（免费版）"),
        ("libsecexe.so", "梆梆安全（免费版）"),
        ("libsecmain.so", "梆梆安全（免费版）"),
        ("secData0.jar", "梆梆安全（免费版）"),
        
        // 海云安
        ("libitsec.so", "海云安加固"),
        ("itse", "海云安加固"),

        // Virbox
        ("ibvirbox32.so", "深盾安全加固（Virbox Protector）"),
        ("libvirbox64.so", "深盾安全加固（Virbox Protector）"),

        // 爱加密
        ("libexec.so", "爱加密"),
        ("libexecmain.so", "爱加密"),
        ("af.bin", "爱加密"),
        ("libijm-emulator.so", "爱加密"),
        ("signed.bin", "爱加密"),
        ("ijiami.dat", "爱加密"),
        ("libexecv3.so", "爱加密3代壳"),
        ("ijiami3.ajm", "爱加密3代壳"),
        ("libijmDataEncryption.so", "爱加密5代壳"),
        ("libijmDataEncryption_x86.so", "爱加密5代壳"),
        ("libijmDataEncryption_x86_64.so", "爱加密5代壳"),
        ("libijmDataEncryption_arm64.so", "爱加密5代壳"),
        ("IJMDal.Data", "爱加密5代壳"),
        ("ijiami.ajm", "爱加密企业版"),

        // 珊瑚灵御
        ("libreincp.so", "珊瑚灵御"),
        ("libreincp_x86.so", "珊瑚灵御"),

        // 瑞星
        ("librsprotect.so", "瑞星加固"),

        // 百度
        ("libbaiduprotect.so", "百度加固"),
        ("libbaiduprotect_x86.so", "百度加固"),
        ("libbaiduprotect_art.so", "百度加固"),
        ("baiduprotect.jar", "百度加固"),
        ("baiduprotect1.jar", "百度加固"),

        // 盛大
        ("libapssec.so", "盛大加固"),

        // 网易
        ("libnesec.so", "网易易盾"),

        // 网秦
        ("libnqshield.so", "网秦加固（国信灵通）"),

        // 腾讯Bugly SDK
        ("libBugly.so", "腾讯Bugly SDK"),

        // 腾讯乐固
        ("libtup.so", "腾讯乐固"),
        ("liblegudb.so", "腾讯乐固"),
        ("libshella", "腾讯乐固"),
        ("libshellx", "腾讯乐固"),
        ("libshel1x.so", "腾讯乐固"),
        ("libshell.so", "腾讯乐固"),
        ("mix.dex", "腾讯乐固"),
        ("mixz.dex", "腾讯乐固"),

        // 腾讯云加固
        ("libshell-super.2019.so", "腾讯云加固"),
        ("libshell-super.2020.so", "腾讯云加固"),
        ("libshell-super.2021.so", "腾讯云加固"),
        ("libshellx-super.2021.so", "腾讯云加固"),
        ("libBugly-yaq.so", "腾讯云移动应用安全"),
        ("libzBugly-yaq.so", "腾讯云移动应用安全"),
        ("libshellx-super.2019.so", "腾讯云移动应用安全"),
        ("tosversion", "腾讯云移动应用安全"),
        ("tosprotection", "腾讯云移动应用安全"),
        ("t86", "腾讯云移动应用安全"),

        // 腾讯云移动应用安全
        ("00O000ll111l.dex", "腾讯云移动应用安全"),
        ("000O00ll111l.dex", "腾讯云移动应用安全"),
        ("0000000lllll.dex", "腾讯云移动应用安全"),
        ("00000olllll.dex", "腾讯云移动应用安全"),
        ("0OO00l111l1l", "腾讯云移动应用安全"),
        ("o0oooOO0ooOo.dat", "腾讯云移动应用安全"),
        ("000000011111.dex", "腾讯御安全"),
        ("000000111111.dex", "腾讯御安全"),
        ("000001111111", "腾讯御安全"),
        ("00000o11111.dex", "腾讯御安全"),
        ("o0ooo000oo0o.dat", "腾讯御安全"),

        // 腾讯御安全
        ("libtosprotection.armeabi-v7a.so", "腾讯御安全"),
        ("libtosprotection.armeabi.so", "腾讯御安全"),
        ("libtosprotection.x86.so", "腾讯御安全"),
        ("libtest.so", "腾讯御安全"),
        ("libTmsdk-xxx-mfr.so", "腾讯御安全"),

        // 腾讯手游加固
        ("libtprt.so", "腾讯手游加固"),

        // 通付盾
        ("libNSaferOnly.so", "通付盾"),
        ("libegis.so", "通付盾"),
        ("libgeiri.so", "通付盾"),
        ("libgeiri-x86.so", "通付盾"),

        // 阿里云加固
        ("libdemolish.so", "阿里云加固"),
        ("libdemolishdata.so", "阿里云加固"),

        // 阿里聚安全
        ("aliprotect.dat", "阿里聚安全"),
        ("libsgmain.so", "阿里聚安全"),
        ("libfakejni.so", "阿里聚安全"),
        ("libzuma.so", "阿里聚安全"),
        ("libzumadata.so", "阿里聚安全"),
        ("libpreverify1.so", "阿里聚安全"),
        ("libdemolish.so", "阿里聚安全"),
        ("libdemolishdata.so", "阿里聚安全"),
        ("libsgsecuritybody.so", "阿里聚安全"),
        ("libmobisec.so", "阿里聚安全"),

        // 顶像科技
        ("libx3g.so", "顶像科技"),
        ("libjni.so", "顶像科技"),

        // Google Play
        ("libpairipcore.so", "Google Play 加固"),

        // LIAPP
        ("LIAPP.ini", "LIAPP加固"),
        ("pkgInfo.txt", "LIAPP加固"),

        // AppGuard
        ("libloader.so", "AppGuard加固"),
        ("AppGuardFrontApplication", "AppGuard加固"),

        // 蛮犀加固
        ("libdSafeShell.so", "蛮犀加固"),
        ("libmxacc.so", "蛮犀加固"),
        ("mxsafe.config", "蛮犀加固"),
        ("mxsafe.data", "蛮犀加固"),
        ("mxsafe.jar", "蛮犀加固"),

        // OPPO安全检测SDK（非加固判据）
        ("libomesStdSco.so", "OPPO安全检测SDK"),

        // 未知厂商
        ("libapk-protect.so", "APKProtect 商业"),
    ])
}

fn main() {
    let args = Args::parse();

    match (args.apk, args.dir) {
        (Some(apk), None) => {
            if let Err(e) = scan_apk(&apk) {
                eprintln!("扫描 {} 失败: {}", apk, e);
            }
        }
        (None, Some(dir)) => {
            if let Err(e) = scan_dir(&dir) {
                eprintln!("批量扫描目录 {} 失败: {}", dir, e);
            }
        }
        (None, None) => {
            eprintln!("用法：");
            eprintln!("  Rsapkid <apk路径>        扫描单个APK");
            eprintln!("  Rsapkid -d <文件夹路径>  批量扫描文件夹内所有APK");
            eprintln!("使用 -h / --help 查看详细帮助");
        }
        // clap 的 conflicts_with 已经拦截同时传 apk 和 -d，这里不会走到
        (Some(_), Some(_)) => unreachable!(),
    }
}
