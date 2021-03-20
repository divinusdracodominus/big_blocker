#[macro_use]
extern crate serde_derive;
use big_blocker::{AWSRange, Blocker, GoogleRange, Range};
use structopt::StructOpt;

#[derive(StructOpt, Debug, Clone, Serialize, Deserialize)]
pub struct Args {
    #[structopt(short, long)]
    pub block: Vec<String>,
    #[structopt(short, long)]
    pub reset: bool,
}
// amazon address: https://ip-ranges.amazonaws.com/ip-ranges.json
// google address: https://www.gstatic.com/ipranges/goog.json
// google cloud addresses: https://www.gstatic.com/ipranges/cloud.json

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::from_args();
    if args.block.is_empty() && !args.reset {
        eprintln!("pointless not the block anything");
    }
    if args.reset {
        Blocker::unblock_all().await?;
    }
    if args.block.contains(&String::from("amazon")) {
        let aws_range: AWSRange = serde_json::from_str(
            &reqwest::get("https://ip-ranges.amazonaws.com/ip-ranges.json")
                .await?
                .text()
                .await?,
        )?;
        let blocker: Blocker = Blocker::new(aws_range.prefixes().unwrap(), false);
        blocker.block().await.unwrap();
    }

    if args.block.contains(&String::from("google")) {
        let cloud_blocker = Blocker::new(serde_json::from_str::<GoogleRange>(
            &reqwest::get("https://www.gstatic.com/ipranges/cloud.json")
                .await?
                .text()
                .await?,
        )?.prefixes().unwrap(), false);
        cloud_blocker.block().await.unwrap();
        let google_range: GoogleRange = serde_json::from_str(
            &reqwest::get("https://www.gstatic.com/ipranges/goog.json")
                .await?
                .text()
                .await?,
        )?;
        let blocker: Blocker = Blocker::new(google_range.prefixes().unwrap(), false);
        blocker.block().await.unwrap();
        
    }
    Ok(())
}