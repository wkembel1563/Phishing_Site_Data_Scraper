

from pkgs.phisherman import Phisherman
from pkgs.util import process_args, save_csv, remove_duplicate_urls


def crawl():
    start, end = process_args()
    phisherman = Phisherman(start, end)
    data = phisherman.crawl()
    remove_duplicate_urls(data, "log.csv", data_type="dictionary")
    save_csv(data, "new.csv", "w")

    # assume log.csv already has data in it
    save_csv(data, "log.csv", "a")

crawl()
