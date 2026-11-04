//! `gexc dsc-info`: what a dyld shared cache holds, as gex-ld reads it.

use anyhow::{bail, Context, Result};
use gex_ld::dsc;
use std::io::{Read, Seek, SeekFrom};
use std::process::ExitCode;

fn uuid(u: &[u8; 16]) -> String {
    u.iter().map(|b| format!("{b:02X}")).collect()
}

fn prot(p: u32) -> String {
    let f = |bit, c| if p & bit != 0 { c } else { '-' };
    [f(dsc::PROT_READ, 'r'), f(dsc::PROT_WRITE, 'w'), f(dsc::PROT_EXEC, 'x')].iter().collect()
}

/// The first `len` bytes of a cache file: enough for its header and tables.
fn head(path: &str, len: usize) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
    let mut b = vec![0u8; len];
    let n = f.read(&mut b)?;
    b.truncate(n);
    Ok(b)
}

fn read_at(path: &str, off: u64, len: u64) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {path}"))?;
    f.seek(SeekFrom::Start(off))?;
    let mut b = vec![0u8; len as usize];
    f.read_exact(&mut b).with_context(|| format!("reading {len:#x} bytes at {off:#x} of {path}"))?;
    Ok(b)
}

/// Rebase every slid mapping of one file at a zero slide and count the
/// pointers that land inside the shared region, against those that do not.
fn check_slide(path: &str, h: &dsc::Header, region: (u64, u64)) -> Result<(u64, u64)> {
    let (mut inside, mut outside) = (0u64, 0u64);
    for m in &h.mappings {
        let Some((si_off, si_size)) = m.slide_info else { continue };
        let info = read_at(path, si_off, si_size)?;
        let mut data = read_at(path, m.file_offset, m.size)?;
        dsc::apply_slide_visit(&mut data, &info, 0, &mut |_, v| {
            // A plain pointer's top byte is a tag, not part of the address.
            let a = v & 0x00ff_ffff_ffff_ffff;
            if a >= region.0 && a < region.1 {
                inside += 1;
            } else {
                outside += 1;
            }
        })?;
    }
    Ok((inside, outside))
}

pub fn cmd(args: &[String]) -> Result<ExitCode> {
    let mut path = None;
    let (mut images, mut slide) = (false, false);
    for a in args {
        match a.as_str() {
            "--images" => images = true,
            "--check-slide" => slide = true,
            p => path = Some(p.to_string()),
        }
    }
    let Some(path) = path else { bail!("usage: gexc dsc-info <dyld_shared_cache> [--images] [--check-slide]") };
    let main = head(&path, 8 << 20)?;
    let h = dsc::parse_header(&main)?;
    println!("{path}: {} uuid {}", h.magic, uuid(&h.uuid));
    println!(
        "  platform {} os {}.{}.{}, shared region {:#x}+{:#x}, max slide {:#x}",
        h.platform,
        h.os_version >> 16,
        (h.os_version >> 8) & 0xff,
        h.os_version & 0xff,
        h.shared_region_start,
        h.shared_region_size,
        h.max_slide
    );
    if let Some((mh, entry)) = h.dyld_in_cache {
        println!("  dyld in cache: header {mh:#x}, entry {entry:#x}");
    }
    println!("  {} images, {} subcaches", h.images.len(), h.subcaches.len());
    let mut files = vec![(path.clone(), h.clone())];
    for sc in &h.subcaches {
        let p = format!("{path}{}", sc.suffix);
        let sh = dsc::parse_header(&head(&p, 1 << 20)?).with_context(|| format!("parsing {p}"))?;
        if sh.uuid != sc.uuid {
            bail!("{p}: uuid {} is not the {} the main file names", uuid(&sh.uuid), uuid(&sc.uuid));
        }
        files.push((p, sh));
    }
    let region = (h.shared_region_start, h.shared_region_start + h.shared_region_size);
    for (p, fh) in &files {
        let name = p.rsplit('/').next().unwrap_or(p);
        for m in &fh.mappings {
            let si = match m.slide_info {
                Some((o, _)) => format!(" slide v{}", dsc::slide_version(&read_at(p, o, 4)?)?),
                None => String::new(),
            };
            println!("  {name:<32} {:#014x}..{:#014x} {}{si}", m.address, m.address + m.size, prot(m.init_prot));
        }
    }
    if images {
        for i in &h.images {
            println!("  {:#014x} {}", i.address, i.path);
        }
    }
    if slide {
        let (mut inside, mut outside) = (0u64, 0u64);
        for (p, fh) in &files {
            let (i, o) = check_slide(p, fh, region)?;
            inside += i;
            outside += o;
        }
        println!("  rebased {} pointers: {inside} in the shared region, {outside} outside", inside + outside);
        if outside > inside / 100 {
            bail!("too many rebased pointers fall outside the shared region");
        }
    }
    Ok(ExitCode::SUCCESS)
}
