/// PostgreSQL stores `lock_timeout` and `statement_timeout` as signed 32-bit
/// millisecond GUCs. Values above this limit are rejected by PostgreSQL.
pub const MAX_TIMEOUT_MS: u64 = i32::MAX as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedSetting<T> {
    pub default: T,
    pub session: T,
    pub effective: T,
}

impl<T: Clone> ScopedSetting<T> {
    pub fn new(default: T) -> Self {
        Self {
            session: default.clone(),
            effective: default.clone(),
            default,
        }
    }

    pub fn reset_effective_to_session(&mut self) {
        self.effective = self.session.clone();
    }
}

/// Parse PostgreSQL's documented timeout syntax and normalize it to the
/// integer millisecond representation used by its timeout GUCs.
pub fn parse_timeout_ms(raw: &str) -> Result<u64, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("timeout value is empty".to_string());
    }

    let bytes = value.as_bytes();
    let mut number_end = usize::from(bytes.first() == Some(&b'+'));
    let unsigned_start = number_end;
    let hexadecimal = bytes
        .get(number_end..number_end + 2)
        .is_some_and(|prefix| prefix == b"0x" || prefix == b"0X");
    if hexadecimal {
        number_end += 2;
        let digits_start = number_end;
        while bytes.get(number_end).is_some_and(u8::is_ascii_hexdigit) {
            number_end += 1;
        }
        if number_end == digits_start {
            return Err(format!("invalid timeout value '{raw}'"));
        }
    } else {
        let mut mantissa_digits = 0;
        while bytes.get(number_end).is_some_and(u8::is_ascii_digit) {
            number_end += 1;
            mantissa_digits += 1;
        }
        if bytes.get(number_end) == Some(&b'.') {
            number_end += 1;
            while bytes.get(number_end).is_some_and(u8::is_ascii_digit) {
                number_end += 1;
                mantissa_digits += 1;
            }
        }
        if mantissa_digits == 0 {
            return Err(format!("invalid timeout value '{raw}'"));
        }
        if matches!(bytes.get(number_end), Some(b'e' | b'E')) {
            number_end += 1;
            if matches!(bytes.get(number_end), Some(b'+' | b'-')) {
                number_end += 1;
            }
            let exponent_start = number_end;
            while bytes.get(number_end).is_some_and(u8::is_ascii_digit) {
                number_end += 1;
            }
            if number_end == exponent_start {
                return Err(format!("invalid timeout value '{raw}'"));
            }
        }
    }
    let (number, unit) = value.split_at(number_end);
    let unsigned_number = &number[unsigned_start..];
    let integer_part_end = unsigned_number
        .find(['.', 'e', 'E'])
        .unwrap_or(unsigned_number.len());
    if !hexadecimal
        && unsigned_number.starts_with('0')
        && unsigned_number[..integer_part_end]
            .bytes()
            .any(|digit| matches!(digit, b'8' | b'9'))
    {
        // PostgreSQL first calls strtol with base 0. An 8 or 9 terminates a
        // leading-octal integer before it can fall back to decimal parsing.
        return Err(format!("invalid timeout value '{raw}'"));
    }
    let numeric = if hexadecimal {
        u64::from_str_radix(&unsigned_number[2..], 16)
            .map(|value| value as f64)
            .map_err(|_| format!("invalid timeout value '{raw}'"))?
    } else if !unsigned_number.contains(['.', 'e', 'E']) && unsigned_number.starts_with('0') {
        u64::from_str_radix(unsigned_number, 8)
            .map(|value| value as f64)
            .map_err(|_| format!("invalid timeout value '{raw}'"))?
    } else {
        number
            .parse::<f64>()
            .map_err(|_| format!("invalid timeout value '{raw}'"))?
    };
    if !numeric.is_finite() || numeric.is_sign_negative() {
        return Err(format!("invalid timeout value '{raw}'"));
    }

    let multiplier = match unit.trim() {
        "" | "ms" => 1.0,
        "us" => 0.001,
        "s" => 1_000.0,
        "min" => 60_000.0,
        "h" => 3_600_000.0,
        "d" => 86_400_000.0,
        _ => return Err(format!("invalid timeout unit in '{raw}'")),
    };
    let milliseconds = numeric * multiplier;
    if !milliseconds.is_finite() || milliseconds > MAX_TIMEOUT_MS as f64 + 0.5 {
        return Err(format!(
            "timeout value '{raw}' exceeds PostgreSQL's maximum"
        ));
    }
    // PostgreSQL's integer GUC parser uses C `rint`, which rounds halfway
    // values to the nearest even integer under its default rounding mode.
    let rounded = milliseconds.round_ties_even() as u64;
    if rounded > MAX_TIMEOUT_MS {
        return Err(format!(
            "timeout value '{raw}' exceeds PostgreSQL's maximum"
        ));
    }
    Ok(rounded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_documented_time_units_into_milliseconds() {
        assert_eq!(parse_timeout_ms("0").unwrap(), 0);
        assert_eq!(parse_timeout_ms("500").unwrap(), 500);
        assert_eq!(parse_timeout_ms("1500 us").unwrap(), 2);
        assert_eq!(parse_timeout_ms("1.5ms").unwrap(), 2);
        assert_eq!(parse_timeout_ms("2.5ms").unwrap(), 2);
        assert_eq!(parse_timeout_ms("3.5ms").unwrap(), 4);
        assert_eq!(parse_timeout_ms("1e-3s").unwrap(), 1);
        assert_eq!(parse_timeout_ms("0x10ms").unwrap(), 16);
        assert_eq!(parse_timeout_ms("010ms").unwrap(), 8);
        assert_eq!(parse_timeout_ms("1.5s").unwrap(), 1_500);
        assert_eq!(parse_timeout_ms("2min").unwrap(), 120_000);
        assert_eq!(parse_timeout_ms("1h").unwrap(), 3_600_000);
        assert_eq!(parse_timeout_ms("1d").unwrap(), 86_400_000);
    }

    #[test]
    fn rejects_negative_unknown_and_out_of_range_values() {
        assert!(parse_timeout_ms("-1").is_err());
        assert!(parse_timeout_ms("1sec").is_err());
        assert!(parse_timeout_ms("NaN").is_err());
        assert!(parse_timeout_ms("1e+s").is_err());
        assert!(parse_timeout_ms("09ms").is_err());
        assert!(parse_timeout_ms("08.0ms").is_err());
        assert!(parse_timeout_ms("2147483648ms").is_err());
    }
}
