# Proiect pentru a rezolva problema cu biletele la Balul Bobocilor

## 1. Ce ne propunem prin acest proiect?

Să rezolvăm problema cu unicitatea și scanarea biletelor prin implementarea unei aplicații web funcționale care să permită verificarea unui UID înregistrat automat în momentul cumpărării biletelor.

## 2. Cum funcționează?

1. Utilizatorul își creează un cont (cu confirmarea parolei) și își verifică adresa de email.
2. După autentificare, poate cumpăra bilete pentru Balul Bobocilor FMI.
3. Fiecare bilet primește automat un UID unic, salvat în baza de date în momentul cumpărării.
4. La intrare, biletul este verificat pe baza UID-ului, astfel încât un bilet nu poate fi folosit de două ori.
5. Administratorii au o pagină separată, accesibilă doar cu cont de admin, pentru gestionarea biletelor.

## 3. Tehnologii folosite

- Python + Flask
- Oracle Database (`oracledb`)
- Șabloane Jinja (HTML), CSS și JavaScript

## 4. Structura proiectului

```
├── app.py            # aplicația Flask (rute, logica serverului)
├── templates/        # paginile HTML (index, signin, signup, verify, bilete, admin)
├── static/           # style.css, app.js, imagini
└── README.md
```

## 5. Rulare locală

```bash
git clone https://github.com/valexandrei/aplicatie_bal.git
cd aplicatie_bal
python -m venv venv
venv\Scripts\activate
pip install flask oracledb
python app.py
```

Aplicația rulează apoi pe `http://127.0.0.1:5000`.

Pentru conectarea la baza de date Oracle, datele de acces se pun într-un fișier `.env` (care nu se urcă pe GitHub).
