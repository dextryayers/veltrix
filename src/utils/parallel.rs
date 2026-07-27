use rayon::prelude::*;

pub fn parallel_map<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> R + Send + Sync,
{
    items.into_par_iter().map(f).collect()
}

pub fn parallel_filter<T, F>(items: Vec<T>, predicate: F) -> Vec<T>
where
    T: Send,
    F: Fn(&T) -> bool + Send + Sync,
{
    items.into_par_iter().filter(predicate).collect()
}

pub fn parallel_flat_map<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> Vec<R> + Send + Sync,
{
    items.into_par_iter().flat_map(f).collect()
}

pub fn parallel_for_each<T, F>(items: Vec<T>, f: F)
where
    T: Send,
    F: Fn(T) + Send + Sync,
{
    items.into_par_iter().for_each(f);
}

pub fn parallel_sort<T: Ord + Send>(items: &mut [T]) {
    items.par_sort();
}

pub fn parallel_sort_by<T, F>(items: &mut [T], compare: F)
where
    T: Send,
    F: Fn(&T, &T) -> std::cmp::Ordering + Send + Sync,
{
    items.par_sort_by(compare);
}

pub fn parallel_unique<T: Ord + Send + Clone>(items: Vec<T>) -> Vec<T> {
    let mut items = items;
    items.par_sort();
    items.dedup();
    items
}

pub fn parallel_dedup<T: Ord + Send>(items: &mut Vec<T>) {
    items.par_sort();
    items.dedup();
}

pub fn password_mutation_parallel(base: &[String], max_mutations: usize) -> Vec<String> {
    let common_subs: Vec<(char, &str)> = vec![
        ('a', "@"), ('e', "3"), ('i', "1"), ('o', "0"),
        ('s', "$"), ('s', "5"), ('t', "7"),
    ];

    base.par_iter()
        .flat_map_iter(|pw| {
            let pw = pw.clone();
            let mut results = Vec::with_capacity(max_mutations / base.len().max(1) + 1);
            results.push(pw.clone());

            let upper = pw.to_uppercase();
            if upper != pw { results.push(upper); }
            let lower = pw.to_lowercase();
            if lower != pw { results.push(lower); }

            for (ch, rep) in &common_subs {
                if pw.contains(*ch) {
                    results.push(pw.replace(*ch, rep));
                }
            }

            if pw.len() >= 2 {
                let last_char = pw.chars().last().unwrap();
                if last_char.is_ascii_digit() {
                    let num: usize = last_char.to_digit(10).unwrap() as usize;
                    if num < 9 { results.push(format!("{}{}", &pw[..pw.len()-1], num + 1)); }
                    if num > 0 { results.push(format!("{}{}", &pw[..pw.len()-1], num - 1)); }
                }
                results.push(format!("{}!", pw));
                results.push(format!("{}@", pw));
                results.push(format!("{}#", pw));
                results.push(format!("{}2024", pw));
                results.push(format!("{}2025", pw));
                results.push(format!("{}2026", pw));
            }

            results.truncate(max_mutations / base.len().max(1));
            results
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_map() {
        let result = parallel_map(vec![1, 2, 3, 4], |x| x * 2);
        assert_eq!(result, vec![2, 4, 6, 8]);
    }

    #[test]
    fn test_parallel_filter() {
        let result = parallel_filter(vec![1, 2, 3, 4, 5, 6], |x| x % 2 == 0);
        assert_eq!(result, vec![2, 4, 6]);
    }

    #[test]
    fn test_parallel_unique() {
        let result = parallel_unique(vec![3, 1, 2, 1, 3, 2]);
        assert_eq!(result, vec![1, 2, 3]);
    }

    #[test]
    fn test_password_mutation_parallel() {
        let base = vec!["password".to_string(), "admin".to_string()];
        let result = password_mutation_parallel(&base, 100);
        assert!(!result.is_empty());
        assert!(result.contains(&"password".to_string()));
        assert!(result.contains(&"PASSWORD".to_string()));
    }

    #[test]
    fn test_empty_parallel_map() {
        let v: Vec<i32> = vec![];
        let result = parallel_map(v, |x| x);
        assert!(result.is_empty());
    }
}
