# OTP-Manager

OTP-Manager is a secure, easy-to-use tool designed to manage one-time passwords (OTP) for various applications.  
It supports **TOTP** (Time-based One-Time Password) and integrates seamlessly with various authentication systems.  
The app is completely offline and stores data locally in an SQLite database.

> ℹ️ **Note:** In **version 2.1.0**, a new feature will be introduced to **customize the server port** and other advanced configuration options.

---

## ✨ Features

- **TOTP support** with configurable refresh times
- **Company grouping** for OTP entries (companies can act like folders)
- **Pinned OTPs** for quick access
- **Customizable UI settings** per user (colors, display options, timers)
- **Built-in logger** with daily log files viewable in the admin panel
- **Multiple companies** with a configurable number of OTP secrets (test DB generator included)
- **Advanced search bar** available on **all pages** to instantly search for:
  - Companies
  - Stored secrets (by name or email)
- **Offline-first** — no internet required

---

## 📦 Installation

### Prerequisites
- Python **3.6+**
- Flask

### Steps

1. Clone the repository:
    ```bash
    git clone https://github.com/Migrim/OTP-Manager.git
    ```
2. Navigate to the project directory:
    ```bash
    cd OTP-Manager
    ```
3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
    
5. Run the application:
    ```bash
    python app.py
    ```

---

## ⚙️ Configuration

The default database is stored at:
instance/otp.db

Default **admin credentials**:
- **Username:** `admin`
- **Password:** `1234`

> ⚠️ Change the admin password immediately after first login.

---

## Screenshots

![Login _ OTP-Tool](https://github.com/user-attachments/assets/41ea52d9-799c-433f-9dae-cabe8233722b)
![Login _ OTP-Tool · 5 27pm · 08-08](https://github.com/user-attachments/assets/88c1091f-573d-4feb-bdf7-7dbfd77c8089)
![Home _ OTP-Tool](https://github.com/user-attachments/assets/ad2bcb01-440b-429f-b524-b47b5a7cf0eb)
![Home _ OTP-Tool · 5 27pm · 08-08](https://github.com/user-attachments/assets/ac69aa4b-1d94-4444-9fbc-3a9af3ef808f)
![Add Entry _ OTP-Tool](https://github.com/user-attachments/assets/3040ef71-bf72-43d0-b219-1e6e6a5e9c3b)
![Add Entry _ OTP-Tool · 5 28pm · 08-08](https://github.com/user-attachments/assets/1b456c90-87bf-4c26-bb83-2dcee551a57d)
![Users _ OTP-Tool](https://github.com/user-attachments/assets/a2894c19-6799-4d36-a2ea-ab1e094634c0)
![Users _ OTP-Tool · 5 28pm · 08-08](https://github.com/user-attachments/assets/2c1c86cc-df53-439e-9ff1-a7ce291935ab)
![Home _ OTP-Tool · 5 28pm · 08-08](https://github.com/user-attachments/assets/e9822525-a089-4e1a-8983-22f4042a5813)


## 🚀 Usage

1. Open your browser and go to:
    ```
    http://localhost:7440
    ```
2. Log in with your credentials.
3. To **add a company**:
    - Go to `Management > Company Settings`
    - Enter company details (name, Kundennummer, optional password)
4. To **add an OTP**:
    - Click `Add`
    - Fill in name, secret, email (optional), refresh time, and company
5. **Search anywhere**:
    - Use the **advanced search bar** at the top of every page
    - Search by **company name**, **secret name**, or **email**
    - Results appear instantly with matching entries
6. **Pin** frequently used OTPs for quick access
7. Admins can view **logs** at `/logs`

---


## 📜 License
This project is licensed under the MIT License.

