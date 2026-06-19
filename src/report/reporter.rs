// FILE: src/report/reporter.rs

use crate::report::violations::{Violation, ViolationTier};
use crate::analysis::state::Confidence;

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
            let clean_recipe = v
                .recipe
                .lines()
                .map(|line| line.trim())
                .collect::<Vec<_>>()
                .join("\n                          ");

            match v.tier {
                ViolationTier::Tier1 => {
                    tier1 += 1;
                    has_tier1_failures = true;
                    println!("[FAIL] [TIER 1 - DANGER ] {}", v.title);
                }
                ViolationTier::Tier2 => {
                    tier2 += 1;
                    println!("[WARN] [TIER 2 - WARNING] {}", v.title);
                }
                ViolationTier::Tier3 => {
                    tier3 += 1;
                    println!("[ OK ] [TIER 3 - SAFE   ] {}", v.title);
                }
            }
            
            println!("                          Rule:   {}", v.rule_id);
            println!("                          Recipe: {}", clean_recipe);
            
            println!("{:-<80}", "");
        }

        println!(); 
        println!("==================================================");
        println!("Analysis Complete.");
        
        match confidence {
            Confidence::Exact => println!("Analysis Confidence : Exact"),
            Confidence::Tainted => println!("Analysis Confidence : Tainted (Dynamic/Opaque SQL detected)"),
        }
        
        println!("Tier 1 (Halt Build) : {}", tier1);
        println!("Tier 2 (Warning)    : {}", tier2);
        println!("Tier 3 (Info)       : {}", tier3);
        println!("==================================================");

        has_tier1_failures
    }
}
