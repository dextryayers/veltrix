use super::credential::Credential;

/// Mode ekspansi kredensial tanpa mengalokasi seluruh matriks di awal.
///
/// Tujuannya adalah Fase 1: handle wordlist besar tanpa OOM dengan cara
/// lazy iterator + batch pull. Pemanggil cukup menarik `next_batch(n)`
/// berulang kali sampai `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpandMode {
    /// users x passwords, urutan stabil: target luar, credential dalam.
    Cartesian,
    /// Spray: satu password ke semua user dulu, lalu password berikutnya.
    /// Lebih aman terhadap lockout untuk audit sensitif.
    Spray,
    /// Hanya user pertama dikombinasikan dengan semua password.
    SingleUser,
}

#[derive(Debug, Clone)]
pub struct CredentialStream {
    users: Vec<String>,
    passwords: Vec<String>,
    mode: ExpandMode,
    user_idx: usize,
    pass_idx: usize,
    /// Untuk mode Cartesian klasik kita iterasi password dalam, user luar.
    /// Untuk Spray kita iterasi user dalam, password luar.
    outer: usize,
    inner: usize,
    done: bool,
}

impl CredentialStream {
    pub fn new(users: Vec<String>, passwords: Vec<String>, mode: ExpandMode) -> Self {
        let done = users.is_empty() || passwords.is_empty();
        Self {
            users,
            passwords,
            mode,
            user_idx: 0,
            pass_idx: 0,
            outer: 0,
            inner: 0,
            done,
        }
    }

    pub fn cartesian(users: Vec<String>, passwords: Vec<String>) -> Self {
        Self::new(users, passwords, ExpandMode::Cartesian)
    }

    /// Estimasi total tanpa ekspansi. Murah dan akurat untuk ketiga mode.
    pub fn estimate_total(&self) -> u64 {
        match self.mode {
            ExpandMode::Cartesian | ExpandMode::Spray => {
                self.users.len() as u64 * self.passwords.len() as u64
            }
            ExpandMode::SingleUser => self.passwords.len() as u64,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    fn next_one(&mut self) -> Option<Credential> {
        if self.done {
            return None;
        }
        match self.mode {
            ExpandMode::Cartesian => {
                if self.outer >= self.users.len() {
                    self.done = true;
                    return None;
                }
                let cred = Credential::new(
                    self.users[self.outer].clone(),
                    self.passwords[self.inner].clone(),
                );
                self.inner += 1;
                if self.inner >= self.passwords.len() {
                    self.inner = 0;
                    self.outer += 1;
                }
                Some(cred)
            }
            ExpandMode::Spray => {
                if self.outer >= self.passwords.len() {
                    self.done = true;
                    return None;
                }
                let cred = Credential::new(
                    self.users[self.inner].clone(),
                    self.passwords[self.outer].clone(),
                );
                self.inner += 1;
                if self.inner >= self.users.len() {
                    self.inner = 0;
                    self.outer += 1;
                }
                Some(cred)
            }
            ExpandMode::SingleUser => {
                if self.users.is_empty() {
                    self.done = true;
                    return None;
                }
                if self.inner >= self.passwords.len() {
                    self.done = true;
                    return None;
                }
                let cred = Credential::new(
                    self.users[0].clone(),
                    self.passwords[self.inner].clone(),
                );
                self.inner += 1;
                Some(cred)
            }
        }
    }

    /// Tarik maksimal `n` kredensial. Mengembalikan vec kosong saat habis.
    pub fn next_batch(&mut self, n: usize) -> Vec<Credential> {
        let mut out = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            match self.next_one() {
                Some(c) => out.push(c),
                None => break,
            }
        }
        out
    }

    /// Sisa estimasi, berguna untuk progress adaptif.
    pub fn remaining_estimate(&self) -> u64 {
        self.estimate_total().saturating_sub(self.produced())
    }

    fn produced(&self) -> u64 {
        match self.mode {
            ExpandMode::Cartesian => self.outer as u64 * self.passwords.len() as u64 + self.inner as u64,
            ExpandMode::Spray => self.outer as u64 * self.users.len() as u64 + self.inner as u64,
            ExpandMode::SingleUser => self.inner as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cartesian_order_and_total() {
        let mut s = CredentialStream::cartesian(
            vec!["a".into(), "b".into()],
            vec!["1".into(), "2".into()],
        );
        assert_eq!(s.estimate_total(), 4);
        let b = s.next_batch(10);
        assert_eq!(b.len(), 4);
        assert_eq!(b[0].username, "a");
        assert_eq!(b[0].password, "1");
        assert_eq!(b[1].password, "2");
        assert_eq!(b[2].username, "b");
        assert!(s.next_batch(10).is_empty());
    }

    #[test]
    fn spray_order_password_outer() {
        let mut s = CredentialStream::new(
            vec!["a".into(), "b".into()],
            vec!["1".into(), "2".into()],
            ExpandMode::Spray,
        );
        let b = s.next_batch(4);
        assert_eq!(b[0].password, "1");
        assert_eq!(b[1].password, "1");
        assert_eq!(b[1].username, "b");
        assert_eq!(b[2].password, "2");
    }

    #[test]
    fn single_user_only_first() {
        let mut s = CredentialStream::new(
            vec!["a".into(), "b".into()],
            vec!["1".into(), "2".into(), "3".into()],
            ExpandMode::SingleUser,
        );
        assert_eq!(s.estimate_total(), 3);
        let b = s.next_batch(10);
        assert!(b.iter().all(|c| c.username == "a"));
    }

    #[test]
    fn empty_is_done() {
        let mut s = CredentialStream::cartesian(vec![], vec!["x".into()]);
        assert!(s.next_batch(5).is_empty());
    }

    #[test]
    fn batch_pull_is_stable() {
        let mut s = CredentialStream::cartesian(
            (0..100).map(|i| format!("u{}", i)).collect(),
            (0..100).map(|i| format!("p{}", i)).collect(),
        );
        assert_eq!(s.estimate_total(), 10_000);
        let mut total = 0;
        while !s.is_done() {
            total += s.next_batch(256).len();
        }
        assert_eq!(total, 10_000);
    }
}
