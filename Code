import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import string
import secrets
import pyperclip


def check_password_strength(password):
    strength = 0
    remarks = ''
    lower_count = upper_count = num_count = wspace_count = special_count = 0

    for char in password:
        if char in string.ascii_lowercase:
            lower_count += 1
        elif char in string.ascii_uppercase:
            upper_count += 1
        elif char in string.digits:
            num_count += 1
        elif char == ' ':
            wspace_count += 1
        else:
            special_count += 1

    if lower_count >= 1:
        strength += 1
    if upper_count >= 1:
        strength += 1
    if num_count >= 1:
        strength += 1
    if wspace_count >= 1:
        strength += 1
    if special_count >= 1:
        strength += 1

    percentage = (strength / 5) * 100  # Calculate percentage

    if strength == 1:
        remarks = 'That\'s a very bad password. Change it as soon as possible.'
    elif strength == 2:
        remarks = 'That\'s a weak password. You should consider using a tougher password.'
    elif strength == 3:
        remarks = 'Your password is okay, but it can be improved.'
    elif strength == 4:
        remarks = 'Your password is hard to guess. But you could make it even more secure.'
    elif strength == 5:
        remarks = 'Now that\'s one hell of a strong password!!! Hackers don\'t have a chance guessing that password!'

    return f'Your password has:\n{lower_count} lowercase letters\n{upper_count} uppercase letters\n{num_count} digits\n{wspace_count} whitespaces\n{special_count} special characters\nPassword Score: {strength}/5 ({percentage:.0f}%)\nRemarks: {remarks}', strength, percentage


def check_password():
    password = password_entry.get()
    result, strength, percentage = check_password_strength(password)
    output_text.config(state='normal')
    output_text.delete('1.0', 'end')
    output_text.insert('end', result)
    output_text.config(state='disabled')

    # Update progress bar color and percentage display
    if strength < 3:
        strength_meter["style"] = "Red.Horizontal.TProgressbar"
        strength_label.config(text=f"Strength: Weak ({percentage:.0f}%)")
    elif strength < 5:
        strength_meter["style"] = "Orange.Horizontal.TProgressbar"
        strength_label.config(text=f"Strength: Medium ({percentage:.0f}%)")
    else:
        strength_meter["style"] = "Green.Horizontal.TProgressbar"
        strength_label.config(text=f"Strength: Strong ({percentage:.0f}%)")

    animate_progress_bar(strength_meter, strength * 20, 0)


def generate_password():
    password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(12))
    password_entry.delete(0, 'end')
    password_entry.insert('end', password)


def copy_password():
    password = password_entry.get()
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Password Copied", "Password copied to clipboard successfully!")
    else:
        messagebox.showwarning("No Password", "No password to copy!")


def clear_input():
    password_entry.delete(0, 'end')
    strength_label.config(text="Strength: ")


def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.destroy()


def animate_progress_bar(progressbar, target_value, current_value):
    if current_value < target_value:
        progressbar["value"] = current_value
        root.after(10, animate_progress_bar, progressbar, target_value, current_value + 1)


# UI Setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("700x500")
root.config(bg="#e0f7fa")

frame = tk.Frame(root, bg="#b2ebf2", padx=20, pady=20)
frame.pack(fill=tk.BOTH, expand=True)

label = tk.Label(frame, text="Enter the password:", bg="#b2ebf2", fg="#00695c", font=("Arial", 14))
label.grid(row=0, column=0, padx=5, pady=5, sticky="e")

password_entry = tk.Entry(frame, show="*", font=("Arial", 12), width=30, borderwidth=2, relief="groove")
password_entry.grid(row=0, column=1, padx=5, pady=5, sticky="we")

check_button = tk.Button(frame, text="Check", command=check_password, bg="#00796b", fg="white", font=("Arial", 12))
check_button.grid(row=1, column=0, pady=10, padx=5, sticky="we")

generate_button = tk.Button(frame, text="Generate Password", command=generate_password, bg="#388e3c", fg="white",
                            font=("Arial", 12))
generate_button.grid(row=1, column=1, pady=10, padx=5, sticky="we")

copy_button = tk.Button(frame, text="Copy Password", command=copy_password, bg="#ff9800", fg="black",
                        font=("Arial", 12))
copy_button.grid(row=1, column=2, pady=10, padx=5, sticky="we")

clear_button = tk.Button(frame, text="Clear", command=clear_input, bg="#d32f2f", fg="white", font=("Arial", 12))
clear_button.grid(row=1, column=3, pady=10, padx=5, sticky="we")

output_text = tk.Text(frame, height=10, width=70, state='disabled', font=("Arial", 10), bg="#ffffff", fg="#000000", borderwidth=2, relief="flat")
output_text.grid(row=2, column=0, columnspan=4, pady=10)

strength_meter = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=450, mode='determinate', value=0,
                                  style="Blue.Horizontal.TProgressbar")
strength_meter.grid(row=3, column=0, columnspan=4, pady=12)

strength_label = tk.Label(frame, text="Strength: ", bg="#b2ebf2", fg="#000000", font=("Arial", 14))
strength_label.grid(row=4, column=0, columnspan=4)

# Bind the password entry to update the strength check
password_entry.bind("<KeyRelease>", lambda event: check_password())

# Set styles for the progress bar
style = ttk.Style()
style.configure("Red.Horizontal.TProgressbar", background="red")
style.configure("Orange.Horizontal.TProgressbar", background="orange")
style.configure("Green.Horizontal.TProgressbar", background="green")
style.configure("Blue.Horizontal.TProgressbar", background="blue")

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
