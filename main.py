import argparse
import sys
from utils.logger import Logger
from core.layered import crack_layers
from core.reporter import Reporter
from core.detector import detect


def banner():
    print(r"""
   _____ _       _               __   __
  / ____(_)     | |             \ \ / /
 | |     _ _ __ | |__   ___ _ __\ V / 
 | |    | | '_ \| '_ \ / _ \ '__|> <  
 | |____| | |_) | | | |  __/ |  / . \ 
  \_____|_| .__/|_| |_|\___|_| /_/ \_\
          | |       by Dreadonyx
          |_|  github.com/Dreadonyx
    """)
    print("  Multi-layer CTF Cipher/Encoding Auto-Cracker\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="CipherX — Multi-layer CTF cipher cracker",
        formatter_class=argparse.RawTextHelpFormatter
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-a", "--auto", metavar="TEXT",
                      help="Auto-crack mode: provide ciphertext directly")
    mode.add_argument("-i", "--interactive", action="store_true",
                      help="Launch interactive menu")
    mode.add_argument("-f", "--file", metavar="FILE",
                      help="Auto-crack from file")
    mode.add_argument("-d", "--detect", metavar="TEXT",
                      help="Detect encoding type only")

    parser.add_argument("--flag-format", metavar="FORMAT",
                        help="Flag format to stop at (e.g. HTB{ or regex HTB\\{.*\\})")
    parser.add_argument("--layers", type=int, default=3,
                        help="Max decode layers (default: 3)")
    parser.add_argument("--report", choices=["json", "html", "both"],
                        help="Save report after auto-crack")
    parser.add_argument("--output", default="reports/result",
                        help="Output path for report (without extension)")

    return parser.parse_args()


def main():
    banner()
    args = parse_args()
    logger = Logger()

    if args.interactive:
        from core.interactive import run
        run(logger)
        return

    if args.detect:
        candidates = detect(args.detect)
        logger.section(f"Detection results for: {args.detect[:60]}")
        if candidates:
            for method, confidence in candidates:
                bar = "█" * (confidence // 10)
                print(f"  {method:<25} {bar} {confidence}%")
        else:
            logger.warning("No encoding detected")
        return

    # Load text
    if args.file:
        try:
            text = open(args.file).read().strip()
            logger.info(f"Loaded from file: {args.file}")
        except Exception as e:
            logger.error(f"Could not read file: {e}")
            sys.exit(1)
    else:
        text = args.auto

    logger.info(f"Input  : {text[:80]}{'...' if len(text) > 80 else ''}")
    logger.info(f"Layers : {args.layers}")
    logger.info(f"Flag   : {args.flag_format or 'auto-detect'}")
    print()

    result, chain, found = crack_layers(
        text,
        flag_format=args.flag_format,
        max_layers=args.layers,
        logger=logger
    )

    logger.chain(chain if chain else ["No layers decoded"])

    reporter = Reporter(text, result, chain, found, args.flag_format)
    reporter.print_summary()

    if args.report in ("json", "both"):
        reporter.to_json(f"{args.output}.json")
    if args.report in ("html", "both"):
        reporter.to_html(f"{args.output}.html")


if __name__ == "__main__":
    main()
