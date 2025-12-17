import streamlit as st
import pandas as pd
import sqlite3
import hashlib
from datetime import datetime, timedelta

st.set_page_config(page_title="SmartShelf Library", layout="wide")
st.markdown("""
<style>
body { background-color: #f7f9fc; font-family: "Segoe UI", sans-serif; }
h1, h2, h3 { color: #1a73e8; }
.stButton > button {
    background-color: #1a73e8; color: white;
    border: none; border-radius: 8px; padding: 0.5rem 1rem;
}
.stButton > button:hover { background-color: #1669c1; }
.block { background-color: white; border-radius: 12px;
    padding: 1.5rem; box-shadow: 0 4px 10px rgba(0,0,0,0.08);
    margin-bottom: 1rem; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 8px; font-size: 12px; color: white; }
.badge.ISSUED { background-color: #fbbc04; }
.badge.RETURNED { background-color: #34a853; }
.badge.PENDING { background-color: #f87171; }
</style>
""", unsafe_allow_html=True)

DB_NAME = "smart_shelf_library.db"

def run_query(query, params=(), fetch=True):
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        conn.commit()
        return cur.fetchall() if fetch else None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            is_admin BOOLEAN
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS books (
            book_id TEXT PRIMARY KEY,
            title TEXT,
            author TEXT,
            categories TEXT,
            description TEXT,
            total_copies INTEGER,
            available_copies INTEGER,
            published_year INTEGER,
            average_rating REAL,
            num_pages INTEGER,
            ratings_count INTEGER,
            arrival_date TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS borrowings (
            borrowing_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            book_id TEXT,
            issue_date TEXT,
            estimated_return_date TEXT,
            actual_return_date TEXT,
            status TEXT
        )""")
        c.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            request_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            book_id TEXT,
            request_date TEXT,
            status TEXT
        )""")

        # Admin credentials: username M_admin, password admin123
        admin_username = "M_admin"
        admin_password = hash_password("admin123")
        c.execute("SELECT COUNT(*) FROM users WHERE username=?", (admin_username,))
        if c.fetchone()[0] == 0:
            c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                      (admin_username, admin_password, True))
        conn.commit()

def import_books_from_csv(csv_path):
    df = pd.read_csv(csv_path)
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        for _, row in df.iterrows():
            book_id = str(row.get('BookId', '')).strip()
            title = str(row.get('title', '')).strip()
            author = str(row.get('author', '')).strip()
            categories = str(row.get('categories', '')).strip()
            description = str(row.get('description', '')).strip()
            try: total = int(row.get('total_copies', 5))
            except: total = 5
            try: available = int(row.get('available_copies', total))
            except: available = total
            try: published_year = int(row.get('published_year', 0))
            except: published_year = None
            try: average_rating = float(row.get('average_rating', 0.0))
            except: average_rating = None
            try: num_pages = int(row.get('num_pages', 0))
            except: num_pages = None
            try: ratings_count = int(row.get('ratings_count', 0))
            except: ratings_count = None
            arrival_date = str(row.get('arrival_date', datetime.now().strftime('%Y-%m-%d')))
            cur.execute("SELECT COUNT(*) FROM books WHERE book_id=?", (book_id,))
            if cur.fetchone()[0] == 0 and book_id:
                cur.execute("""
                    INSERT INTO books (
                        book_id, title, author, categories, description,
                        total_copies, available_copies, published_year,
                        average_rating, num_pages, ratings_count, arrival_date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    book_id, title, author, categories, description,
                    total, available, published_year,
                    average_rating, num_pages, ratings_count, arrival_date
                ))
        conn.commit()

def should_import():
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM books")
        return cur.fetchone()[0] == 0

def get_user(username):
    res = run_query("SELECT * FROM users WHERE username=?", (username,))
    return res[0] if res else None

def verify_login(username, password):
    user = get_user(username)
    return user if user and user[2] == hash_password(password) else None

def admin_dashboard():
    st.title("👨‍💻 Admin Dashboard")
    menu = st.sidebar.radio("Admin Actions", [
        "📚 Available Books", "🔥 Popular Books",
        "📨 Pending Requests", "↩️ Manage Returns", "👥 User Data", "➕ Add New Book"
    ])
    if menu == "📚 Available Books":
        df = pd.DataFrame(run_query("""
            SELECT book_id, title, author, categories, description, total_copies, available_copies, published_year, average_rating, num_pages, ratings_count, arrival_date
            FROM books"""),
            columns=["Book ID", "Title", "Author", "Categories", "Description", "Total", "Available",
                     "Published Year", "Avg Rating", "Pages", "Ratings Count", "Arrival"])
        st.dataframe(df, use_container_width=True)

    elif menu == "🔥 Popular Books":
        df = pd.DataFrame(run_query("""
            SELECT title, author, average_rating, ratings_count FROM books ORDER BY average_rating DESC LIMIT 10
        """),
            columns=["Title", "Author", "Avg Rating", "Ratings"])
        st.dataframe(df, use_container_width=True)

    elif menu == "📨 Pending Requests":
        df = pd.DataFrame(run_query("""
            SELECT r.request_id, u.username, b.title, r.request_date
            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            JOIN books b ON r.book_id = b.book_id
            WHERE r.status='PENDING'
        """), columns=["Request ID", "User", "Book", "Date"])
        if df.empty:
            st.info("No pending requests.")
        else:
            st.dataframe(df, use_container_width=True)
            req_id = st.number_input("Enter Request ID to process", min_value=1, step=1)
            action = st.radio("Action", ["Accept", "Deny"], horizontal=True)
            if st.button("Process Request"):
                process_request(req_id, action.upper())
                st.rerun()

    elif menu == "↩️ Manage Returns":
        manage_returns()

    elif menu == "👥 User Data":
        uid = st.number_input("Enter User ID:", min_value=1, step=1)
        show_user_borrowing(uid)

    elif menu == "➕ Add New Book":
        add_new_books_form()

def process_request(req_id, action):
    req = run_query("SELECT user_id, book_id FROM requests WHERE request_id=?", (req_id,))
    if not req:
        st.error("Request not found.")
        return
    user_id, book_id = req[0]
    if action == "ACCEPT":
        available = run_query("SELECT available_copies FROM books WHERE book_id=?", (book_id,))
        if available and available[0][0] > 0:
            run_query("UPDATE books SET available_copies = available_copies - 1 WHERE book_id=?", (book_id,), fetch=False)
            issue_date = datetime.now().strftime('%Y-%m-%d')
            est_return = (datetime.now() + timedelta(days=14)).strftime('%Y-%m-%d')
            # Insert record into borrowings table
            run_query("""INSERT INTO borrowings (user_id, book_id, issue_date, estimated_return_date, status)
                         VALUES (?, ?, ?, ?, 'ISSUED')""", (user_id, book_id, issue_date, est_return), fetch=False)
            run_query("UPDATE requests SET status='ACCEPTED' WHERE request_id=?", (req_id,), fetch=False)
            st.success("✅ Book issued successfully.")
        else:
            st.warning("Book unavailable.")
            run_query("UPDATE requests SET status='DENIED' WHERE request_id=?", (req_id,), fetch=False)
    else:
        run_query("UPDATE requests SET status='DENIED' WHERE request_id=?", (req_id,), fetch=False)
        st.warning("Request denied.")

def manage_returns():
    df = pd.DataFrame(run_query("""
        SELECT br.borrowing_id, u.username, b.title, br.issue_date, br.estimated_return_date
        FROM borrowings br
        JOIN users u ON br.user_id = u.user_id
        JOIN books b ON br.book_id = b.book_id
        WHERE br.status='ISSUED'
    """), columns=["Borrow ID", "User", "Book", "Issue", "Est. Return"])
    if df.empty:
        st.info("No active borrowings.")
        return
    st.dataframe(df, use_container_width=True)
    bid = st.number_input("Enter Borrow ID to confirm return", min_value=1, step=1)
    if st.button("Confirm Return"):
        run_query("UPDATE borrowings SET status='RETURNED', actual_return_date=? WHERE borrowing_id=?",
                  (datetime.now().strftime('%Y-%m-%d'), bid), fetch=False)
        run_query("UPDATE books SET available_copies = available_copies + 1 WHERE book_id=(SELECT book_id FROM borrowings WHERE borrowing_id=?)",
                  (bid,), fetch=False)
        st.success("📘 Book return confirmed.")
        st.rerun()


def show_user_borrowing(uid):
    df = pd.DataFrame(run_query("""
        SELECT b.title, br.issue_date, br.estimated_return_date, br.status
        FROM borrowings br
        JOIN books b ON br.book_id = b.book_id
        WHERE br.user_id=?
    """, (uid,)), columns=["Book", "Issue", "Return", "Status"])
    if not df.empty:
        df["Status"] = df["Status"].apply(lambda s: f"<span class='badge {s}'>{s}</span>")
        st.markdown(df.to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.info("No data found.")


def add_new_books_form():
    with st.form("new_book"):
        book_id = st.text_input("Book ID")
        t = st.text_input("Book Title")
        a = st.text_input("Author")
        cat = st.text_input("Categories")
        desc = st.text_area("Description")
        c = st.number_input("Total Copies", min_value=1, step=1)
        py = st.number_input("Published Year", min_value=0, step=1)
        ar = st.number_input("Average Rating", min_value=0.0, format="%.2f")
        num_pages = st.number_input("Pages", min_value=1, step=1)
        rc = st.number_input("Ratings Count", min_value=0, step=1)
        if st.form_submit_button("Add Book"):
            run_query("""
                INSERT INTO books (
                    book_id, title, author, categories, description, total_copies,
                    available_copies, published_year, average_rating, num_pages,
                    ratings_count, arrival_date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (book_id, t, a, cat, desc, c, c, py, ar, num_pages, rc, datetime.now().strftime('%Y-%m-%d')),
                fetch=False)
            st.success("New book added successfully!")
            st.rerun()

def user_dashboard():
    user = st.session_state['user']
    st.title(f"📚 Welcome, {user[1]}")
    menu = st.sidebar.radio("User Actions", [
        "🔎 Search Books", "🔥 Popular Books", "🆕 New Arrivals", "📖 My Borrowed Books"
    ])
    if menu == "🔎 Search Books":
        show_books_for_user(user[0])
    elif menu == "🔥 Popular Books":
        df = pd.DataFrame(run_query(
            "SELECT title, author, average_rating, available_copies FROM books ORDER BY average_rating DESC LIMIT 10"),
            columns=["Title", "Author", "Avg Rating", "Available"])
        st.dataframe(df, use_container_width=True)
    elif menu == "🆕 New Arrivals":
        cutoff = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        df = pd.DataFrame(run_query(
            "SELECT title, author, available_copies, arrival_date FROM books WHERE arrival_date >= ?",
            (cutoff,)), columns=["Title", "Author", "Available", "Date"])
        st.dataframe(df, use_container_width=True)
    elif menu == "📖 My Borrowed Books":
        show_user_borrowing(user[0])

def show_books_for_user(uid):
    term = st.text_input("Search by Title or Author")
    df = pd.DataFrame(run_query(
        """
        SELECT book_id, title, author, categories, description, available_copies,
        published_year, average_rating, num_pages, ratings_count
        FROM books WHERE title LIKE ? OR author LIKE ?
        """, (f"%{term}%", f"%{term}%")),
        columns=[
            "ID", "Title", "Author", "Categories", "Description", "Available",
            "Published Year", "Avg Rating", "Pages", "Ratings Count"
        ])
    st.dataframe(df, use_container_width=True)
    bid = st.text_input("Enter Book ID to Request:")
    if st.button("Request Book"):
        check = run_query("SELECT * FROM requests WHERE user_id=? AND book_id=? AND status='PENDING'", (uid, bid))
        if check:
            st.warning("You already requested this book.")
        else:
            run_query("""INSERT INTO requests (user_id, book_id, request_date, status)
                         VALUES (?, ?, ?, 'PENDING')""", (uid, bid, datetime.now().strftime('%Y-%m-%d')), fetch=False)
            st.success("✅ Request sent successfully!")
            st.rerun()

def main_app():
    if 'logged_in' not in st.session_state:
        st.session_state.update({'logged_in': False, 'user': None})

    if st.session_state['logged_in']:
        st.sidebar.success(f"Logged in as {st.session_state['user'][1]}")
        if st.sidebar.button("Logout"):
            st.session_state.update({'logged_in': False, 'user': None})
            st.rerun()
        (admin_dashboard if st.session_state['user'][3] else user_dashboard)()
        return

    st.title("📘 SmartShelf Library System")
    choice = st.radio("Select Action", ["Login", "Register"], horizontal=True)
    st.caption("🔐 Admin login: M_admin / admin123")

    if choice == "Login":
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            user = verify_login(u, p)
            if user:
                st.session_state.update({'logged_in': True, 'user': user})
                st.success("Welcome back!")
                st.rerun()
            else:
                st.error("Invalid credentials.")
    else:
        u = st.text_input("New Username")
        p = st.text_input("New Password", type="password")
        if st.button("Register"):
            if get_user(u):
                st.error("Username already exists.")
            else:
                run_query("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                          (u, hash_password(p), False), fetch=False)
                st.success("Account created successfully. Please log in.")

if __name__ == "__main__":
    init_db()
    if should_import():
        import_books_from_csv("data.csv")
    main_app()
