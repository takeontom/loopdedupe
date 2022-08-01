import argparse
import hashlib
import sqlite3
from os import R_OK, access
from pathlib import Path


def setup_db():
    con = sqlite3.connect("loopdeloop.db")
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
        idx_files_hasg
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
        print(f"{f_posix_path} is not already known")
        f_hash = calc_file_hash(path)
        delete_file_hash(db_con, f_posix_path)
        store_file_hash(db_con, f_posix_path, f_size, f_hash)
    else:
        print(f"{f_posix_path} is already known")

    db_con.commit()


def clean_db(db_con):
    known_paths = select_all_paths(db_con)
    for kp in known_paths:
        path = Path(kp[0])
        if not path.exists() or not path.is_file():
            print(f"{kp} no longer exists, removing from DB")
            delete_file_hash(db_con, kp[0])

    db_con.commit()


def show_duplicates(db_con):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find duplicate files")
    parser.add_argument(
        "paths",
        metavar="paths",
        type=str,
        nargs="+",
        help="paths to directories which should be inspected",
    )

    args = parser.parse_args()

    paths = [Path(p) for p in args.paths]
    paths = [p for p in paths if p.exists() and p.is_dir()]

    db_con = setup_db()

    for path in paths:
        [
            inspect_file(p, db_con)
            for p in path.rglob("*")
            if p.is_file() and access(p, R_OK)
        ]

    clean_db(db_con)