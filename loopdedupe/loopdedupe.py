#!/usr/bin/env python3

import argparse
import hashlib
import sqlite3
from os import R_OK, access
from pathlib import Path


def setup_db(db_path):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS
        files (
            path text PRIMARY KEY,
            size int,
            hash text
        )
    """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS
        idx_files_path_size
        ON files (
            path,
            size
        )
    """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_files_hash
        ON files (
            hash
        )
    """
    )

    return con


def is_file_known(db_con, path, size):
    cursor = db_con.cursor()

    sql = """
        SELECT hash
        FROM files
        WHERE path=? and size=?
    """

    cursor.execute(sql, (path, size))
    result = cursor.fetchall()
    return bool(len(result))


def select_all_paths(db_con):
    cursor = db_con.cursor()

    sql = """
        SELECT path
        FROM files
    """

    cursor.execute(sql)
    result = cursor.fetchall()
    return result


def store_file_hash(db_con, f_path, f_size, f_hash):
    cursor = db_con.cursor()

    sql = """
        INSERT INTO files
        VALUES (?, ?, ?)
    """

    cursor.execute(sql, (f_path, f_size, f_hash))


def delete_file_hash(db_con, f_path):
    cursor = db_con.cursor()

    sql = """
        DELETE FROM files
        WHERE path = ?
    """

    cursor.execute(sql, (f_path,))


def select_duplicate_hashes(db_con):
    cursor = db_con.cursor()

    sql = """
        SELECT f.path, f.size, h.hash_count, f.hash
        FROM files as f
        JOIN (
            SELECT hash, count(*) AS hash_count
            FROM files
            GROUP BY hash
            HAVING hash_count > 1
        ) h ON f.hash = h.hash
        WHERE f.size > 0
        ORDER BY h.hash_count ASC, f.hash ASC
    """

    cursor.execute(sql)
    result = cursor.fetchall()
    return result


def calc_file_hash(path: Path):
    file_hash = hashlib.blake2b()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            file_hash.update(chunk)

    return file_hash.hexdigest()


def inspect_file(path: Path, db_con):
    f_size = path.stat().st_size
    f_posix_path = path.absolute().as_posix()

    if not is_file_known(db_con, f_posix_path, f_size):
        print(f"adding:\t{f_posix_path}")
        f_hash = calc_file_hash(path)
        delete_file_hash(db_con, f_posix_path)
        store_file_hash(db_con, f_posix_path, f_size, f_hash)
    else:
        print(f"known:\t{f_posix_path}")

    db_con.commit()


def clean_db(db_con):
    known_paths = select_all_paths(db_con)
    for kp in known_paths:
        path = Path(kp[0])
        if not path.exists() or not path.is_file():
            print(f"{kp} no longer exists, removing from DB")
            delete_file_hash(db_con, kp[0])

    db_con.commit()


def handle_duplicates(db_con):
    duplicates = select_duplicate_hashes(db_con)

    current_hash = None
    for f_path, f_size, hash_count, f_hash in duplicates:
        if current_hash != f_hash:
            print("")
            print(f"{f_path} ({f_size} bytes) has {hash_count} duplicates:")
            current_hash = f_hash

        print(f"\t{f_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Find duplicate files in the supplied paths",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        default=False,
        help="don't scan for unknown files",
    )
    parser.add_argument(
        "--skip-clean",
        action="store_true",
        default=False,
        help="don't clean deleted files from database",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="./loopdedupe.db",
        help="path to database file. Database Will be created if it does not exist",
    )
    parser.add_argument(
        "paths",
        metavar="paths",
        type=str,
        nargs="+",
        help="paths to directories which should be inspected",
    )

    args = parser.parse_args()
    print(args)

    paths = [Path(p) for p in args.paths]
    paths = [p for p in paths if p.exists() and p.is_dir()]

    db_con = setup_db(args.db)

    if args.skip_scan:
        print("Skipping scan")
    else:
        for path in paths:
            [
                inspect_file(p, db_con)
                for p in path.rglob("*")
                if p.is_file() and access(p, R_OK)
            ]

    if args.skip_clean:
        print("Skipping clean")
    else:
        clean_db(db_con)

    handle_duplicates(db_con)


if __name__ == "__main__":
    main()
