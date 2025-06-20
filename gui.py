import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from AntiVirusScan import scan_single_file, scan_directory_recursively

API_KEY = "4368a2eb7db33b07cc73175d0787e1bca74406838db159749809d32d11984b06"

def scan_single_file_gui():
    file_path = filedialog.askopenfilename()
    if file_path:
        result = scan_single_file(file_path, API_KEY)
        if result == -1:
            messagebox.showerror("Scan Result", "❌ Error during scan")
        elif result == 0:
            messagebox.showinfo("Scan Result", "✅ The file is clean")
        else:
            messagebox.showwarning("Scan Result", "⚠️ WARNING: The file is malicious!")

def scan_directory_gui():
    folder_path = filedialog.askdirectory()
    if folder_path:
        results = scan_directory_recursively(folder_path, API_KEY)
        for file, result in results:
            if result == -1:
                messagebox.showerror("Scan Result", f"Error scanning {file}")
            elif result == 0:
                messagebox.showinfo("Scan Result", f"{file} is clean")
            else:
                messagebox.showwarning("Scan Result", f"{file} is malicious!")

def show_help():
    help_text = (
        "Instructions:\n"
        "- Click 'SCAN FILE' to select and scan a single file.\n"
        "- Click 'SCAN PATH' to select and scan a folder.\n"
        "- Please wait about 15 seconds for the scan to complete.\n"
        "- You will see a popup with the scan result for each file."
    )
    messagebox.showinfo("Help", help_text)

def create_gui():
    window = tk.Tk()
    window.title("Anti-Virus Scanner")
    window.geometry("768x1152")
    window.resizable(False, False)

    bg_image = Image.open("a4957974-2444-41b1-a7f1-50b7fcf7483e.png")
    bg_image = bg_image.resize((768, 1152))
    bg_photo = ImageTk.PhotoImage(bg_image)

    global canvas
    canvas = tk.Canvas(window, width=768, height=1152, highlightthickness=0)
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, image=bg_photo, anchor="nw")

    def create_click_area(x, y, width, height, command):
        rect = canvas.create_rectangle(x, y, x + width, y + height, fill='', outline='')
        canvas.tag_bind(rect, "<Button-1>", lambda e: command())


    create_click_area(130, 240, 170, 170, scan_single_file_gui)
    create_click_area(470, 240, 170, 170, scan_directory_gui)
    create_click_area(130, 680, 170, 120, window.destroy)
    create_click_area(470, 680, 170, 120, show_help)
        

    window.mainloop()

if __name__ == "__main__":
    create_gui()
