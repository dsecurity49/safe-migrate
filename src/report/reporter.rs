// FILE: src/report/reporter.rs
use crate::analysis::state::Confidence;
use crate::report::violations::{Violation, ViolationTier};

pub struct Reporter;

impl Reporter {
    pub fn print_report(violations: &[Violation], confidence: &Confidence) -> bool {
        let mut tier1 = 0;
        let mut tier2 = 0;
        let mut tier3 = 0;
        let mut has_tier1_failures = false;

        if violations.is_empty() {
            println!("No schema locks or violations detected.");
            return false;
        }

        println!("{:-<80}", "");

        for v in violations {
            // Indent by exactly 9 spaces to align under the 8-character tags + 1 space
            let indent = "         ";
            let clean_recipe = v
                .recipe
                .lines()
                .map(|line| line.trim())
                .collect::<Vec<_>>()
                .join(&format!("\n{}", indent));

            match v.tier {
                ViolationTier::Tier1 => {
                    tier1 += 1;
                    has_tier1_failures = true;
                    println!("[ HALT ] {}", v.title);
                }
                ViolationTier::Tier2 => {
                    tier2 += 1;
                    println!("[ WARN ] {}", v.title);
                }
                ViolationTier::Tier3 => {
                    tier3 += 1;
                    println!("[ SAFE ] {}", v.title);
                }
            }

            println!("{}Rule:   {}", indent, v.rule_id);
            println!("{}Recipe: {}", indent, clean_recipe);

            println!("{:-<80}", "");
        }

        println!();
        println!("==================================================");
        println!("Analysis Complete");
        println!("==================================================");

        let conf_str = match confidence {
            Confidence::Exact => "Exact",
            Confidence::Tainted => "Tainted (Dynamic/Opaque SQL)",
        };

        println!("Confidence: {}", conf_str);
        println!("--------------------------------------------------");
        println!("[ HALT ] Tier 1: {}", tier1);
        println!("[ WARN ] Tier 2: {}", tier2);
        println!("[ SAFE ] Tier 3: {}", tier3);
        println!("==================================================");

        has_tier1_failures
    }
}
