#!/usr/bin/env python3
import os
import sys
import argparse
import pymysql

def get_visual_width(s):
    width = 0
    for char in s:
        if ord(char) > 127:
            width += 2
        else:
            width += 1
    return width

def pad_string(s, width):
    s_width = get_visual_width(s)
    if s_width >= width:
        return s
    return s + " " * (width - s_width)

def print_table(headers, rows):
    if not headers:
        return

    # 计算每一列的视觉对齐宽度
    widths = [get_visual_width(str(h)) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            val_str = str(val) if val is not None else "NULL"
            val_width = get_visual_width(val_str)
            if val_width > widths[i]:
                widths[i] = val_width

    # 限制单列最大宽度，防止内容过长撑破屏幕
    max_col_width = 80
    widths = [min(w, max_col_width) for w in widths]

    # 打印边框
    border = "+" + "+".join(["-" * (w + 2) for w in widths]) + "+"
    print(border)

    # 打印表头
    header_items = []
    for i, h in enumerate(headers):
        val_str = str(h)
        if get_visual_width(val_str) > widths[i]:
            val_str = val_str[:widths[i]-3] + "..."
        header_items.append(f" {pad_string(val_str, widths[i])} ")
    print("|" + "|".join(header_items) + "|")
    print(border)

    # 打印行数据
    for row in rows:
        row_items = []
        for i, val in enumerate(row):
            val_str = str(val) if val is not None else "NULL"
            if get_visual_width(val_str) > widths[i]:
                val_str = val_str[:widths[i]-3] + "..."
            row_items.append(f" {pad_string(val_str, widths[i])} ")
        print("|" + "|".join(row_items) + "|")

    print(border)
    print(f"{len(rows)} rows in set\n")

def execute_sql(cursor, sql):
    # 处理 USE database 语句
    sql_clean = sql.strip().rstrip(";").strip()
    if sql_clean.lower().startswith("use "):
        db_name = sql_clean[4:].strip().strip("`").strip("'").strip('"')
        try:
            cursor.execute(f"USE `{db_name}`")
            print(f"Database changed to {db_name}\n")
            return
        except Exception as e:
            print("Error:", e, "\n")
            return

    try:
        cursor.execute(sql)
        # 区分是否有结果集返回
        if cursor.description:
            headers = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            print_table(headers, rows)
        else:
            print(f"Query OK, {cursor.rowcount} row affected\n")
    except Exception as e:
        print("Error:", e, "\n")

def main():
    parser = argparse.ArgumentParser(description="MySQL-Lite PyMySQL CLI")
    parser.add_argument("-H", "--host", default="127.0.0.1")
    parser.add_argument("-P", "--port", type=int, default=3306)
    parser.add_argument("-u", "--user", default="root")
    parser.add_argument("-p", "--password", default=os.getenv("MYSQL_PASSWORD", ""))
    parser.add_argument("-D", "--database", default="bind_cache_analyze")
    args = parser.parse_args()

    print("Connecting to MySQL server...")
    try:
        conn = pymysql.connect(
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password,
            database=args.database,
            charset="utf8mb4",
            autocommit=True
        )
    except Exception as e:
        print("Failed to connect:", e)
        sys.exit(1)

    cursor = conn.cursor()
    buffer = []
    print("Welcome to the MySQL-Lite monitor. Commands end with ;. Type 'exit' or 'quit' to quit.\n")

    # 初始化交互式 shell
    while True:
        try:
            prompt = "mysql-lite> " if not buffer else "    -> "
            line = input(prompt)
            if not line:
                if not buffer:
                    continue

            clean_line = line.strip()
            if not buffer and clean_line.lower() in ("exit", "quit", "exit;", "quit;"):
                break

            buffer.append(line)
            if clean_line.endswith(";"):
                sql = " ".join(buffer)
                buffer = []
                execute_sql(cursor, sql)
        except KeyboardInterrupt:
            print("\nQuery cancelled.")
            buffer = []
        except EOFError:
            print("\nBye")
            break

    cursor.close()
    conn.close()
    print("Bye")

if __name__ == "__main__":
    main()
