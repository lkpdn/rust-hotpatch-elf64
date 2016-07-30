extern crate elf;
extern crate regex;
extern crate libc;
extern crate byteorder;
extern crate posix_ipc as ipc;
extern crate ptrace;
use std::mem;
use std::ptr;
use std::io;
use util::GenError;

pub fn set_data(pid:i32, addr: u64, buf: Vec<u8>, size: usize) -> Result<(), GenError> {
    let writer = ptrace::Writer::new(pid);
    info!("set_data(addr:{}, size:{})", addr, size);
    writer.write_data(addr as u64, &buf)
      .map_err(|e| GenError::RawOsError(e))
}

pub fn dump_canvas<T: io::Write>(canvas: *mut libc::c_void, buf_size: usize, writer: &mut T) {
    let mut buffer: Vec<u8> = Vec::new();
    let mut line_start: usize = 0;
    let mut last_line_zeros: bool = false;
    for i in 0...buf_size {
        if buffer.len() == 32 || i == buf_size {
            match buffer
              .iter()
              .fold(0, |acc, &x| {
                  if x > 0 { acc + 1}
                  else { acc }
              }) {
                0 => {
                    if last_line_zeros == false {
                        writeln!(writer, "{}", ":").unwrap();
                    }
                    last_line_zeros = true;
                },
                _ => {
                    last_line_zeros = false;
                    write!(writer, "0x{:0>16x}:", line_start).unwrap();
                    for j in 0..buffer.len() {
                        if j % 8 == 0 { write!(writer, "{}", " ").unwrap(); }
                        else if j % 4 == 0 { write!(writer, "{}", "_").unwrap(); }
                        write!(writer, "{:0>2x}", buffer[j]).unwrap();
                    }
                    writeln!(writer, "").unwrap();
                }
            }
        }
        if buffer.len() == 32 {
            line_start = i;
            buffer.drain(..);
        }
        if i == buf_size { break }
        unsafe {
            let read_byte = ptr::read_volatile(
                mem::transmute::<*mut libc::c_void, *mut u8>(
                    canvas.offset(i as isize)
                )
            );
            buffer.push(read_byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc;
    use std::ptr::copy_nonoverlapping;
    use std::ffi::CString;

    #[test]
    fn test_dump_canvas() {
        let data = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
        ];
        let mut w: Vec<u8> = vec![0; data.len()];
        unsafe {
            let canvas: *mut libc::c_void = libc::malloc(data.len());
            let buf = CString::from_vec_unchecked(data.clone());
            let buf_addr: *mut libc::c_void = buf.as_ptr() as *mut libc::c_void;
            copy_nonoverlapping(buf_addr, canvas, data.len());
            dump_canvas(canvas, data.len(), &mut w);
            libc::free(canvas);
        }
        assert_eq!(w[227..232], [10, 58, 10, 48, 120]);
    }
}
