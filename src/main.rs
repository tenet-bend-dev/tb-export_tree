use chrono::{DateTime, Local};
use clap::Parser;
use jwalk::WalkDir;
use std::fs::{self, File};
use std::io::{Write, BufWriter};
use std::path::{Path, PathBuf};
use windows::Win32::Storage::FileSystem::{GetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM};

#[derive(Parser)]
#[command(author, version, about = "Professional Directory Auditor")]
struct Args {
    /// The target directory to scan (Defaults to current folder if empty)
    path: Option<PathBuf>,

    /// Maximum recursion depth (e.g., 2 to see only top folders)
    #[arg(short, long)]
    depth: Option<usize>,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    
    // Determine target: 1. Command line Arg, 2. Drag-and-Drop, 3. Current Dir
    let target_root = args.path
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to get current dir"));
    
    // Create a unique log name based on the folder scanned
    let folder_name = target_root.file_name().unwrap_or_default().to_string_lossy();
    let output_name = if folder_name.is_empty() { "audit_root.txt".to_string() } else { format!("audit_{}.txt", folder_name) };
    let output_path = std::env::current_dir()?.join(output_name);
    
    let file = File::create(&output_path)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "System Audit for: {}", target_root.display())?;
    writeln!(writer, "Generated: {}", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    if let Some(d) = args.depth { writeln!(writer, "Max Depth Limit: {}", d)?; }
    writeln!(writer, "\nTREE STRUCTURE")?;
    writeln!(writer, "--------------")?;

    // Parallel walk with optional depth limit
    let mut walker = WalkDir::new(&target_root).sort(true);
    if let Some(max_d) = args.depth {
        walker = walker.max_depth(max_d);
    }

    let entries: Vec<_> = walker.into_iter().filter_map(|e| e.ok()).collect();

    // 1. Build the Tree View
    for entry in &entries {
        let depth = entry.depth;
        let indent = "    ".repeat(depth);
        let prefix = if depth > 0 { "├── " } else { "" };
        let name = entry.file_name.to_string_lossy();
        let marker = if entry.file_type.is_dir() { "[DIR]" } else { "[FILE]" };
        
        writeln!(writer, "{}{}{} {}", indent, prefix, name, marker)?;
    }

    writeln!(writer, "\nDETAILED AUDIT LOG")?;
    writeln!(writer, "------------------")?;

    // 2. Build Detailed Descriptions
    for entry in &entries {
        let path = entry.path();
        let metadata = fs::metadata(&path).ok();
        let rel_path = path.strip_prefix(&target_root).unwrap_or(&path);
        
        let mut audit_line = format!("Path: {} -- ", rel_path.display());

        if let Some(meta) = metadata {
            let size = meta.len();
            let modified: DateTime<Local> = meta.modified()?.into();
            let attr_str = get_windows_attributes(&path);
            
            audit_line.push_str(&format!(
                "Size: {} bytes; Modified: {}; Attr: {}; ",
                size, 
                modified.format("%Y-%m-%d %H:%M:%S"),
                attr_str
            ));
        }

        let file_type = if entry.file_type.is_dir() { "Type: directory" } else { "Type: file" };
        audit_line.push_str(file_type);
        writeln!(writer, "{}", audit_line)?;
    }

    println!("Audit complete for: {}", target_root.display());
    println!("Results written to: {}", output_path.display());
    
    // CRITICAL: Pause if a path was provided (like drag-and-drop) so you can read the success message
    if std::env::args().count() > 1 {
        println!("\n[DONE] Press Enter to close this window...");
        let mut _temp = String::new();
        let _ = std::io::stdin().read_line(&mut _temp);
    }

    Ok(())
}

fn get_windows_attributes(path: &Path) -> String {
    use windows::core::HSTRING;
    let path_h = HSTRING::from(path.as_os_str());
    unsafe {
        let attr = GetFileAttributesW(&path_h);
        if attr == 0xFFFFFFFF { return "Unknown".to_string(); }
        let mut flags = Vec::new();
        if attr & FILE_ATTRIBUTE_HIDDEN.0 != 0 { flags.push("Hidden"); }
        if attr & FILE_ATTRIBUTE_SYSTEM.0 != 0 { flags.push("System"); }
        if flags.is_empty() { "Normal".to_string() } else { flags.join("+") }
    }
}