extern crate ptrace;
extern crate libc;
extern crate posix_ipc as ipc;
use self::ptrace::*;
use std::ptr;
use std::ops::Range;
use util::GenError;

pub trait SyscallExt {
    fn dispatch(&self) -> Result<u64, usize>;
}

impl SyscallExt for Syscall {
    fn dispatch(&self) -> Result<u64, usize> {
        let code = 0x9090909090cc050f;
        let o_regs = try!(getregs(self.pid));
        let mut n_regs = o_regs.clone();
        n_regs.rip -= 8;
        let reader = ptrace::Reader::new(self.pid);
        let o_rip = try!(reader.peek_data(n_regs.rip));
        debug!("o_rip: {}", o_rip);
        let writer = ptrace::Writer::new(self.pid);
        try!(writer.poke_data(n_regs.rip, code));
        n_regs.rdi = self.args[0];
        n_regs.rsi = self.args[1];
        n_regs.rdx = self.args[2];
        n_regs.rcx = self.args[3];
        n_regs.r8 = self.args[4];
        n_regs.r9 = self.args[5];
        n_regs.orig_rax = self.call;
        n_regs.rax = self.return_val;
        debug!("n_regs: {:?}", n_regs);
        try!(setregs(self.pid, &n_regs));
        try!(cont(self.pid, ipc::signals::Signal::None));
        unsafe { waitpid(self.pid, ptr::null_mut(), 0) };
        let m_regs = try!(getregs(self.pid));
        try!(setregs(self.pid, &o_regs));
        try!(writer.poke_data(n_regs.rip, o_rip));
        Ok((m_regs.rax))
    }
}

pub fn check_range_contains_rip(pid: i32, rng: Range<u64>)
  -> Result<bool, GenError> {
    let regs = try!(getregs(pid).map_err(|e| GenError::RawOsError(e)));
    if rng.contains(regs.rip) { Ok(true) }
    else { Ok(false) }
}

extern "C" {
    fn waitpid(pid: libc::pid_t, status: *mut libc::c_int, options: libc::c_int) -> libc::c_int;
}

#[cfg(test)]
mod tests {
    extern crate libc;
    use std::ptr;
    use super::ptrace;
    use super::SyscallExt;
    use super::check_range_contains_rip;

    #[test]
    fn dispatch() {
        let pid = fork_and_halt();
        ptrace::attach(pid).ok().expect("Could not attach to child");
        unsafe { waitpid(pid, ptr::null_mut(), 0) };
        let syscall = ptrace::Syscall {
            args: [0; 6],
            call: 0,
            pid: pid,
            return_val: 39 // getpid
        };
        assert_eq!(syscall.dispatch().unwrap() as libc::c_int, pid);
    }

    fn fork_and_halt() -> libc::c_int {
        match unsafe { fork() } {
            0 => { loop { unsafe { raise(19); } } },
            v => v
        }
    }

    #[test]
    fn test_check_range_contains_rip() {
        let pid = fork_and_halt();
        ptrace::attach(pid).ok().expect("Could not attach to child");
        unsafe { waitpid(pid, ptr::null_mut(), 0) };
        assert_eq!(check_range_contains_rip(pid, (0x0u64..0x1u64)).unwrap(), false);
        assert_eq!(check_range_contains_rip(pid, (0x0u64..0xffffffff_ffffffffu64)).unwrap(), true);
    }

    extern "C" {
        fn fork() -> libc::pid_t;
        fn raise(signal: libc::c_int) -> libc::c_int;
        fn waitpid(pid: libc::pid_t, status: *mut libc::c_int,
          options: libc::c_int) -> libc::c_int;
    }
}
