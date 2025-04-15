import datetime
import sqlite3
from tkcalendar import DateEntry
from tkinter import *
import tkinter.messagebox as mb
import tkinter.ttk as ttk
import hashlib
from fpdf import FPDF
import pandas as pd
from PIL import Image, ImageTk
import os
from tkinter import filedialog

# Database setup
connector = sqlite3.connect("Expense Tracker.db")
cursor = connector.cursor()

# Create tables if they don't exist
connector.execute(
    'CREATE TABLE IF NOT EXISTS ExpenseTracker (ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, Date DATETIME, Payee TEXT, Description TEXT, Amount FLOAT, ModeOfPayment TEXT)'
)
connector.execute(
    'CREATE TABLE IF NOT EXISTS Users (ID INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT UNIQUE, Password TEXT, Email TEXT, JoinDate DATETIME)'
)
connector.commit()

# Authentication functions
def hash_password(password):
    """Hash a password for storing."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    return stored_password == hashlib.sha256(provided_password.encode()).hexdigest()

def register_user(username, password, email):
    """Register a new user"""
    try:
        hashed_pw = hash_password(password)
        join_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        connector.execute('INSERT INTO Users (Username, Password, Email, JoinDate) VALUES (?, ?, ?, ?)', 
                         (username, hashed_pw, email, join_date))
        connector.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def authenticate_user(username, password):
    """Authenticate a user"""
    cursor.execute('SELECT Password FROM Users WHERE Username = ?', (username,))
    result = cursor.fetchone()
    if result:
        return verify_password(result[0], password)
    return False

# Stylish Login Window
class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Expense Tracker - Login")
        self.master.geometry("1000x600")
        self.master.resizable(0, 0)
        self.master.configure(bg='#2c3e50')
        
        # Background Frame
        self.bg_frame = Frame(self.master, bg='#2c3e50')
        self.bg_frame.pack(fill=BOTH, expand=True)
        
        # Left Side - App Info
        self.left_frame = Frame(self.bg_frame, bg='#34495e', width=400)
        self.left_frame.pack(side=LEFT, fill=Y)
        self.left_frame.pack_propagate(0)
        
        # App Logo/Title
        self.logo_label = Label(self.left_frame, text="💰", font=('Arial', 80), bg='#34495e', fg='#ecf0f1')
        self.logo_label.pack(pady=(80, 20))
        
        self.app_title = Label(self.left_frame, text="EXPENSE TRACKER", font=('Arial', 24, 'bold'), 
                             bg='#34495e', fg='#ecf0f1')
        self.app_title.pack(pady=(0, 10))
        
        self.app_subtitle = Label(self.left_frame, text="Track your finances with ease", 
                                font=('Arial', 12), bg='#34495e', fg='#bdc3c7')
        self.app_subtitle.pack(pady=(0, 80))
        
        self.features_label = Label(self.left_frame, 
                                  text="• Secure Authentication\n• Expense Management\n• Detailed Reports\n• Data Visualization", 
                                  font=('Arial', 12), bg='#34495e', fg='#ecf0f1', justify=LEFT)
        self.features_label.pack(pady=(0, 50))
        
        # Right Side - Login Form
        self.right_frame = Frame(self.bg_frame, bg='#ecf0f1', width=600)
        self.right_frame.pack(side=RIGHT, fill=BOTH, expand=True)
        self.right_frame.pack_propagate(0)
        
        # Login Form Container
        self.form_frame = Frame(self.right_frame, bg='#ecf0f1')
        self.form_frame.place(relx=0.5, rely=0.5, anchor=CENTER)
        
        # Form Title
        self.form_title = Label(self.form_frame, text="Welcome Back!", font=('Arial', 24, 'bold'), 
                              bg='#ecf0f1', fg='#2c3e50')
        self.form_title.grid(row=0, column=0, columnspan=2, pady=(0, 30))
        
        # Username Field
        self.username_label = Label(self.form_frame, text="Username", font=('Arial', 12), 
                                  bg='#ecf0f1', fg='#7f8c8d')
        self.username_label.grid(row=1, column=0, sticky=W, pady=(10, 5))
        
        self.username_entry = Entry(self.form_frame, font=('Arial', 14), width=25, 
                                  highlightthickness=1, highlightbackground='#bdc3c7')
        self.username_entry.grid(row=2, column=0, columnspan=2, pady=(0, 15))
        self.username_entry.bind("<FocusIn>", lambda e: self.username_entry.config(highlightbackground='#3498db'))
        self.username_entry.bind("<FocusOut>", lambda e: self.username_entry.config(highlightbackground='#bdc3c7'))
        
        # Password Field
        self.password_label = Label(self.form_frame, text="Password", font=('Arial', 12), 
                                  bg='#ecf0f1', fg='#7f8c8d')
        self.password_label.grid(row=3, column=0, sticky=W, pady=(10, 5))
        
        self.password_entry = Entry(self.form_frame, font=('Arial', 14), width=25, 
                                  show="*", highlightthickness=1, highlightbackground='#bdc3c7')
        self.password_entry.grid(row=4, column=0, columnspan=2, pady=(0, 20))
        self.password_entry.bind("<FocusIn>", lambda e: self.password_entry.config(highlightbackground='#3498db'))
        self.password_entry.bind("<FocusOut>", lambda e: self.password_entry.config(highlightbackground='#bdc3c7'))
        
        # Login Button
        self.login_btn = Button(self.form_frame, text="Login", font=('Arial', 14, 'bold'), 
                              bg='#3498db', fg='white', bd=0, padx=30, pady=10,
                              command=self.login)
        self.login_btn.grid(row=5, column=0, columnspan=2, pady=(10, 20))
        self.login_btn.bind("<Enter>", lambda e: self.login_btn.config(bg='#2980b9'))
        self.login_btn.bind("<Leave>", lambda e: self.login_btn.config(bg='#3498db'))
        
        # Register Link
        self.register_label = Label(self.form_frame, text="Don't have an account? ", 
                                  font=('Arial', 11), bg='#ecf0f1', fg='#7f8c8d')
        self.register_label.grid(row=6, column=0, sticky=E)
        
        self.register_link = Label(self.form_frame, text="Register", font=('Arial', 11, 'underline'), 
                                 bg='#ecf0f1', fg='#3498db', cursor="hand2")
        self.register_link.grid(row=6, column=1, sticky=W)
        self.register_link.bind("<Button-1>", lambda e: self.show_register())
        
        # Footer
        self.footer = Label(self.right_frame, text="© 2025 Expense Tracker | Vikash Tiwari", 
                           font=('Arial', 10), bg='#ecf0f1', fg='#7f8c8d')
        self.footer.pack(side=BOTTOM, pady=20)
        
        self.main_app = None
    
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            mb.showerror("Error", "Please enter both username and password")
            return
            
        if authenticate_user(username, password):
            self.master.destroy()
            self.main_app = MainApplication()
        else:
            mb.showerror("Error", "Invalid username or password")
    
    def show_register(self):
        register_window = Toplevel(self.master)
        register_window.title("Create New Account")
        register_window.geometry("500x600")
        register_window.configure(bg='#ecf0f1')
        register_window.resizable(0, 0)
        
        # Register Form Container
        register_form = Frame(register_window, bg='#ecf0f1')
        register_form.pack(pady=50)
        
        # Form Title
        Label(register_form, text="Create Account", font=('Arial', 24, 'bold'), 
             bg='#ecf0f1', fg='#2c3e50').grid(row=0, column=0, columnspan=2, pady=(0, 30))
        
        # Username Field
        Label(register_form, text="Username", font=('Arial', 12), 
             bg='#ecf0f1', fg='#7f8c8d').grid(row=1, column=0, sticky=W, pady=(10, 5))
        
        reg_username = Entry(register_form, font=('Arial', 14), width=25, 
                           highlightthickness=1, highlightbackground='#bdc3c7')
        reg_username.grid(row=2, column=0, columnspan=2, pady=(0, 15))
        
        # Email Field
        Label(register_form, text="Email", font=('Arial', 12), 
             bg='#ecf0f1', fg='#7f8c8d').grid(row=3, column=0, sticky=W, pady=(10, 5))
        
        reg_email = Entry(register_form, font=('Arial', 14), width=25, 
                       highlightthickness=1, highlightbackground='#bdc3c7')
        reg_email.grid(row=4, column=0, columnspan=2, pady=(0, 15))
        
        # Password Field
        Label(register_form, text="Password", font=('Arial', 12), 
             bg='#ecf0f1', fg='#7f8c8d').grid(row=5, column=0, sticky=W, pady=(10, 5))
        
        reg_password = Entry(register_form, font=('Arial', 14), width=25, 
                       show="*", highlightthickness=1, highlightbackground='#bdc3c7')
        reg_password.grid(row=6, column=0, columnspan=2, pady=(0, 20))
        
        # Confirm Password Field
        Label(register_form, text="Confirm Password", font=('Arial', 12), 
             bg='#ecf0f1', fg='#7f8c8d').grid(row=7, column=0, sticky=W, pady=(10, 5))
        
        reg_confirm_password = Entry(register_form, font=('Arial', 14), width=25, 
                                   show="*", highlightthickness=1, highlightbackground='#bdc3c7')
        reg_confirm_password.grid(row=8, column=0, columnspan=2, pady=(0, 30))
        
        # Register Button
        def register():
            username = reg_username.get()
            email = reg_email.get()
            password = reg_password.get()
            confirm_password = reg_confirm_password.get()
            
            if not username or not email or not password or not confirm_password:
                mb.showerror("Error", "Please fill all fields")
                return
                
            if password != confirm_password:
                mb.showerror("Error", "Passwords don't match")
                return
                
            if register_user(username, password, email):
                mb.showinfo("Success", "Account created successfully! Please login.")
                register_window.destroy()
            else:
                mb.showerror("Error", "Username already exists")
        
        Button(register_form, text="Register", font=('Arial', 14, 'bold'), 
              bg='#2ecc71', fg='white', bd=0, padx=30, pady=10,
              command=register).grid(row=9, column=0, columnspan=2, pady=(10, 20))
        
        # Back to Login Link
        back_link = Label(register_form, text="← Back to Login", font=('Arial', 11, 'underline'), 
                        bg='#ecf0f1', fg='#3498db', cursor="hand2")
        back_link.grid(row=10, column=0, columnspan=2)
        back_link.bind("<Button-1>", lambda e: register_window.destroy())

# Main Application (your original code with reporting features)
class MainApplication:
    def __init__(self):
        # Backgrounds and Fonts
        self.dataentery_frame_bg = 'Red'
        self.buttons_frame_bg = 'Tomato'
        self.hlb_btn_bg = 'IndianRed'
        
        self.lbl_font = ('Georgia', 13)
        self.entry_font = 'Times 13 bold'
        self.btn_font = ('Gill Sans MT', 13)
        
        # Initializing the GUI window
        self.root = Tk()
        self.root.title('Vikash Tiwari | Expense Tracker')
        self.root.geometry('1200x650')
        self.root.resizable(0, 0)
        
        # Menu Bar
        self.menu_bar = Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        # File Menu
        self.file_menu = Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Generate Monthly Report (PDF)", command=self.generate_pdf_report)
        self.file_menu.add_command(label="Export to Excel", command=self.export_to_excel)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        
        # Help Menu
        self.help_menu = Menu(self.menu_bar, tearoff=0)
        self.help_menu.add_command(label="About", command=self.show_about)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        
        Label(self.root, text='EXPENSE TRACKER', font=('Noto Sans CJK TC', 15, 'bold'), bg=self.hlb_btn_bg).pack(side=TOP, fill=X)
        
        # StringVar and DoubleVar variables
        self.desc = StringVar()
        self.amnt = DoubleVar()
        self.payee = StringVar()
        self.MoP = StringVar(value='Cash')
        
        # Frames
        self.data_entry_frame = Frame(self.root, bg=self.dataentery_frame_bg)
        self.data_entry_frame.place(x=0, y=30, relheight=0.95, relwidth=0.25)
        
        self.buttons_frame = Frame(self.root, bg=self.buttons_frame_bg)
        self.buttons_frame.place(relx=0.25, rely=0.05, relwidth=0.75, relheight=0.21)
        
        self.tree_frame = Frame(self.root)
        self.tree_frame.place(relx=0.25, rely=0.26, relwidth=0.75, relheight=0.74)
        
        # Data Entry Frame
        self.setup_data_entry_frame()
        # Buttons Frame
        self.setup_buttons_frame()
        # Treeview Frame
        self.setup_tree_frame()
        
        self.list_all_expenses()
        self.root.mainloop()
    
    def setup_data_entry_frame(self):
        Label(self.data_entry_frame, text='Date (M/DD/YY) :', font=self.lbl_font, bg=self.dataentery_frame_bg).place(x=10, y=50)
        self.date = DateEntry(self.data_entry_frame, date=datetime.datetime.now().date(), font=self.entry_font)
        self.date.place(x=160, y=50)
        
        Label(self.data_entry_frame, text='Payee\t             :', font=self.lbl_font, bg=self.dataentery_frame_bg).place(x=10, y=230)
        Entry(self.data_entry_frame, font=self.entry_font, width=31, text=self.payee).place(x=10, y=260)
        
        Label(self.data_entry_frame, text='Description           :', font=self.lbl_font, bg=self.dataentery_frame_bg).place(x=10, y=100)
        Entry(self.data_entry_frame, font=self.entry_font, width=31, text=self.desc).place(x=10, y=130)
        
        Label(self.data_entry_frame, text='Amount\t             :', font=self.lbl_font, bg=self.dataentery_frame_bg).place(x=10, y=180)
        Entry(self.data_entry_frame, font=self.entry_font, width=14, text=self.amnt).place(x=160, y=180)
        
        Label(self.data_entry_frame, text='Mode of Payment:', font=self.lbl_font, bg=self.dataentery_frame_bg).place(x=10, y=310)
        dd1 = OptionMenu(self.data_entry_frame, self.MoP, *['Cash', 'Cheque', 'Credit Card', 'Debit Card', 'Paytm', 'Google Pay', 'Razorpay'])
        dd1.place(x=160, y=305)
        dd1.configure(width=10, font=self.entry_font)
        
        Button(self.data_entry_frame, text='Add expense', command=self.add_another_expense, font=self.btn_font, width=30,
               bg=self.hlb_btn_bg).place(x=10, y=395)
        Button(self.data_entry_frame, text='Convert to words before adding', font=self.btn_font, width=30, 
               bg=self.hlb_btn_bg, command=self.expense_to_words_before_adding).place(x=10, y=450)
    
    def setup_buttons_frame(self):
        Button(self.buttons_frame, text='Delete Expense', font=self.btn_font, width=25, bg=self.hlb_btn_bg, 
               command=self.remove_expense).place(x=30, y=5)
        
        Button(self.buttons_frame, text='Clear Fields in DataEntry Frame', font=self.btn_font, width=25, bg=self.hlb_btn_bg,
               command=self.clear_fields).place(x=335, y=5)
        
        Button(self.buttons_frame, text='Delete All Expenses', font=self.btn_font, width=25, bg=self.hlb_btn_bg, 
               command=self.remove_all_expenses).place(x=640, y=5)
        
        Button(self.buttons_frame, text='View Selected Expense\'s Details', font=self.btn_font, width=25, bg=self.hlb_btn_bg,
               command=self.view_expense_details).place(x=30, y=65)
        
        Button(self.buttons_frame, text='Edit Selected Expense', command=self.edit_expense, font=self.btn_font, width=25, 
               bg=self.hlb_btn_bg).place(x=335, y=65)
        
        Button(self.buttons_frame, text='Convert Expense to a sentence', font=self.btn_font, width=25, bg=self.hlb_btn_bg,
               command=self.selected_expense_to_words).place(x=640, y=65)
    
    def setup_tree_frame(self):
        self.table = ttk.Treeview(self.tree_frame, selectmode=BROWSE, 
                                 columns=('ID', 'Date', 'Payee', 'Description', 'Amount', 'Mode of Payment'))
        
        X_Scroller = Scrollbar(self.table, orient=HORIZONTAL, command=self.table.xview)
        Y_Scroller = Scrollbar(self.table, orient=VERTICAL, command=self.table.yview)
        X_Scroller.pack(side=BOTTOM, fill=X)
        Y_Scroller.pack(side=RIGHT, fill=Y)
        
        self.table.config(yscrollcommand=Y_Scroller.set, xscrollcommand=X_Scroller.set)
        
        self.table.heading('ID', text='S No.', anchor=CENTER)
        self.table.heading('Date', text='Date', anchor=CENTER)
        self.table.heading('Payee', text='Payee', anchor=CENTER)
        self.table.heading('Description', text='Description', anchor=CENTER)
        self.table.heading('Amount', text='Amount', anchor=CENTER)
        self.table.heading('Mode of Payment', text='Mode of Payment', anchor=CENTER)
        
        self.table.column('#0', width=0, stretch=NO)
        self.table.column('#1', width=50, stretch=NO)
        self.table.column('#2', width=95, stretch=NO)  # Date column
        self.table.column('#3', width=150, stretch=NO)  # Payee column
        self.table.column('#4', width=325, stretch=NO)  # Title column
        self.table.column('#5', width=135, stretch=NO)  # Amount column
        self.table.column('#6', width=125, stretch=NO)  # Mode of Payment column
        
        self.table.place(relx=0, y=0, relheight=1, relwidth=1)
    
    # Reporting Functions
    def generate_pdf_report(self):
        """Generate a PDF report of all expenses"""
        try:
            # Get all expenses
            cursor.execute("SELECT * FROM ExpenseTracker")
            expenses = cursor.fetchall()
            
            if not expenses:
                mb.showerror("No Data", "There are no expenses to generate a report")
                return
            
            # Ask for save location
            file_path = filedialog.asksaveasfilename(defaultextension=".pdf", 
                                                    filetypes=[("PDF files", "*.pdf")],
                                                    title="Save PDF Report As")
            if not file_path:
                return
            
            # Create PDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            
            # Title
            pdf.cell(200, 10, txt="Expense Tracker - Monthly Report", ln=1, align='C')
            pdf.ln(10)
            
            # Date
            pdf.cell(200, 10, txt=f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
            pdf.ln(5)
            
            # Table Header
            pdf.set_font("Arial", 'B', size=10)
            pdf.cell(15, 10, "ID", border=1)
            pdf.cell(25, 10, "Date", border=1)
            pdf.cell(40, 10, "Payee", border=1)
            pdf.cell(80, 10, "Description", border=1)
            pdf.cell(25, 10, "Amount", border=1)
            pdf.cell(25, 10, "Payment Mode", border=1, ln=1)
            
            # Table Data
            pdf.set_font("Arial", size=10)
            total = 0
            for expense in expenses:
                pdf.cell(15, 10, str(expense[0]), border=1)
                pdf.cell(25, 10, expense[1], border=1)
                pdf.cell(40, 10, expense[2], border=1)
                pdf.cell(80, 10, expense[3], border=1)
                pdf.cell(25, 10, f"${expense[4]:.2f}", border=1)
                pdf.cell(25, 10, expense[5], border=1, ln=1)
                total += expense[4]
            
            # Total
            pdf.ln(5)
            pdf.set_font("Arial", 'B', size=12)
            pdf.cell(180, 10, f"Total Expenses: ${total:.2f}", ln=1, align='R')
            
            # Save PDF
            pdf.output(file_path)
            mb.showinfo("Success", f"PDF report generated successfully at:\n{file_path}")
            
        except Exception as e:
            mb.showerror("Error", f"Failed to generate PDF: {str(e)}")
    
    def export_to_excel(self):
        """Export expenses to Excel file"""
        try:
            # Get all expenses
            cursor.execute("SELECT * FROM ExpenseTracker")
            expenses = cursor.fetchall()
            
            if not expenses:
                mb.showerror("No Data", "There are no expenses to export")
                return
            
            # Create DataFrame
            df = pd.DataFrame(expenses, columns=['ID', 'Date', 'Payee', 'Description', 'Amount', 'Mode of Payment'])
            
            # Ask for save location
            file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", 
                                                   filetypes=[("Excel files", "*.xlsx")],
                                                   title="Save Excel File As")
            if not file_path:
                return
            
            # Save to Excel
            df.to_excel(file_path, index=False)
            mb.showinfo("Success", f"Data exported to Excel successfully at:\n{file_path}")
            
        except Exception as e:
            mb.showerror("Error", f"Failed to export to Excel: {str(e)}")
    
    def show_about(self):
        """Show about information"""
        about_text = """Expense Tracker v2.0
        
A comprehensive financial management application with:
- Secure user authentication
- Expense tracking and management
- PDF and Excel reporting
- Intuitive user interface

Developed with Python and Tkinter
© 2025 Expense Tracker | Vikash Tiwari"""
        mb.showinfo("About Expense Tracker", about_text)
    
    # All your original functions as methods of the class
    def list_all_expenses(self):
        self.table.delete(*self.table.get_children())
        all_data = connector.execute('SELECT * FROM ExpenseTracker')
        data = all_data.fetchall()
        for values in data:
            self.table.insert('', END, values=values)
    
    def view_expense_details(self):
        if not self.table.selection():
            mb.showerror('No expense selected', 'Please select an expense from the table to view its details')
            return

        current_selected_expense = self.table.item(self.table.focus())
        values = current_selected_expense['values']
        expenditure_date = datetime.date(int(values[1][:4]), int(values[1][5:7]), int(values[1][8:]))
        
        self.date.set_date(expenditure_date)
        self.payee.set(values[2])
        self.desc.set(values[3])
        self.amnt.set(values[4])
        self.MoP.set(values[5])
    
    def clear_fields(self):
        today_date = datetime.datetime.now().date()
        self.desc.set('')
        self.payee.set('')
        self.amnt.set(0.0)
        self.MoP.set('Cash')
        self.date.set_date(today_date)
        self.table.selection_remove(*self.table.selection())
    
    def remove_expense(self):
        if not self.table.selection():
            mb.showerror('No record selected!', 'Please select a record to delete!')
            return

        current_selected_expense = self.table.item(self.table.focus())
        values_selected = current_selected_expense['values']
        surety = mb.askyesno('Are you sure?', f'Are you sure that you want to delete the record of {values_selected[2]}')

        if surety:
            connector.execute('DELETE FROM ExpenseTracker WHERE ID=%d' % values_selected[0])
            connector.commit()
            self.list_all_expenses()
            mb.showinfo('Record deleted successfully!', 'The record you wanted to delete has been deleted successfully')
    
    def remove_all_expenses(self):
        surety = mb.askyesno('Are you sure?', 'Are you sure that you want to delete all the expense items from the database?', icon='warning')
        if surety:
            self.table.delete(*self.table.get_children())
            connector.execute('DELETE FROM ExpenseTracker')
            connector.commit()
            self.clear_fields()
            self.list_all_expenses()
            mb.showinfo('All Expenses deleted', 'All the expenses were successfully deleted')
        else:
            mb.showinfo('Ok then', 'The task was aborted and no expense was deleted!')
    
    def add_another_expense(self):
        if not self.date.get() or not self.payee.get() or not self.desc.get() or not self.amnt.get() or not self.MoP.get():
            mb.showerror('Fields empty!', "Please fill all the missing fields before pressing the add button!")
        else:
            connector.execute(
                'INSERT INTO ExpenseTracker (Date, Payee, Description, Amount, ModeOfPayment) VALUES (?, ?, ?, ?, ?)',
                (self.date.get_date(), self.payee.get(), self.desc.get(), self.amnt.get(), self.MoP.get())
            )
            connector.commit()
            self.clear_fields()
            self.list_all_expenses()
            mb.showinfo('Expense added', 'The expense whose details you just entered has been added to the database')
    
    def edit_expense(self):
        def edit_existing_expense():
            current_selected_expense = self.table.item(self.table.focus())
            contents = current_selected_expense['values']
            connector.execute('UPDATE ExpenseTracker SET Date = ?, Payee = ?, Description = ?, Amount = ?, ModeOfPayment = ? WHERE ID = ?',
                            (self.date.get_date(), self.payee.get(), self.desc.get(), self.amnt.get(), self.MoP.get(), contents[0]))
            connector.commit()
            self.clear_fields()
            self.list_all_expenses()
            mb.showinfo('Data edited', 'We have updated the data and stored in the database as you wanted')
            edit_btn.destroy()

        if not self.table.selection():
            mb.showerror('No expense selected!', 'You have not selected any expense in the table for us to edit; please do that!')
            return

        self.view_expense_details()
        edit_btn = Button(self.data_entry_frame, text='Edit expense', font=self.btn_font, width=30,
                          bg=self.hlb_btn_bg, command=edit_existing_expense)
        edit_btn.place(x=10, y=395)
    
    def selected_expense_to_words(self):
        if not self.table.selection():
            mb.showerror('No expense selected!', 'Please select an expense from the table for us to read')
            return

        current_selected_expense = self.table.item(self.table.focus())
        values = current_selected_expense['values']
        message = f'Your expense can be read like: \n"You paid {values[4]} to {values[2]} for {values[3]} on {values[1]} via {values[5]}"'
        mb.showinfo('Here\'s how to read your expense', message)
    
    def expense_to_words_before_adding(self):
        if not self.date or not self.desc or not self.amnt or not self.payee or not self.MoP:
            mb.showerror('Incomplete data', 'The data is incomplete, meaning fill all the fields first!')
            return

        message = f'Your expense can be read like: \n"You paid {self.amnt.get()} to {self.payee.get()} for {self.desc.get()} on {self.date.get_date()} via {self.MoP.get()}"'
        add_question = mb.askyesno('Read your record like: ', f'{message}\n\nShould I add it to the database?')
        if add_question:
            self.add_another_expense()
        else:
            mb.showinfo('Ok', 'Please take your time to add this record')

# Start the application with login window
if __name__ == "__main__":
    login_root = Tk()
    login_app = LoginWindow(login_root)
    login_root.mainloop()