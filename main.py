# ============================================================
#  CyberShield – Real-Time Cyber Threat Detection
#  Fixed version: real-time detection log fully working
# ============================================================

from tkinter import messagebox
from tkinter import *
from tkinter import simpledialog
import tkinter
from tkinter import filedialog
from tkinter.filedialog import askopenfilename
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
import os
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
import webbrowser
import pickle
from sklearn.decomposition import PCA
from sklearn.preprocessing import MinMaxScaler
import keras
from keras import layers
from keras.models import model_from_json
from keras.utils import to_categorical
from keras.models import Model
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
from tkinter import PhotoImage
from PIL import Image, ImageTk
import threading
import time
import random
import socket
import csv
import queue                          # FIX 1: thread-safe bridge
from datetime import datetime

# Scapy: import gracefully so app still runs without root/admin
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# ── Global state ──────────────────────────────────────────────────────────────
global filename, autoencoder, encoder_model, pca
global X, Y, dataset
global accuracy, precision, recall, fscore, vector
global X_train, X_test, y_train, y_test, scaler

# FIX 2: every model starts as None so `if model is None` checks work correctly
encoder_model = None
pca           = None
random_forest = None
mlp           = None
scaler        = None
autoencoder   = None
X             = None
Y             = None

monitoring    = False
traffic_data  = []
detection_log = []

# FIX 3: queue lets background threads hand work to the main thread safely
_work_queue = queue.Queue()

labels = [
    'Phishing',
    'Denial of Service (DoS)',
    'Distributed Denial of Service (DDoS)',
    'Man-in-the-Middle (MITM)',
    'SQL Injection',
    'Cross-Site Scripting (XSS)',
    'Zero-Day Exploit',
    'Brute Force Attack',
]

# ── Tkinter window ────────────────────────────────────────────────────────────
main = tkinter.Tk()
main.title("REAL-TIME CYBER THREAT DETECTION")
main.geometry("1300x1200")

# =============================================================
#  REAL-TIME DETECTION ENGINE
# =============================================================

def generate_network_features():
    """Random feature vector in [0,1] matching the dataset width."""
    n = X.shape[1] if X is not None else 40
    return [random.uniform(0, 1) for _ in range(n)]


def capture_packet(packet):
    """Scapy callback – runs in scapy's background thread."""
    if not monitoring:
        return
    try:
        if IP not in packet:
            return
        n = X.shape[1] if X is not None else 40
        feats = [0.0] * n
        feats[0] = len(packet[IP]) / 65535.0
        feats[1] = 1.0 if TCP in packet else (0.5 if UDP in packet else 0.0)
        feats[2] = packet[IP].ttl / 255.0
        feats[3] = len(packet[IP].payload) / 65535.0
        # FIX 4: push to queue instead of calling Keras from this thread
        _work_queue.put(feats)
    except Exception as e:
        print("capture_packet error:", e)


def generate_simulated_traffic():
    """Background thread: produces one simulated packet every 0.5-1.5 s."""
    while monitoring:
        time.sleep(random.uniform(0.5, 1.5))
        if monitoring:
            # FIX 4 (same): push to queue, never call Keras here
            _work_queue.put(generate_network_features())


def _poll_queue():
    """
    FIX 4 – Runs on the MAIN thread via main.after().
    Drains the queue and calls Keras safely.
    """
    try:
        while True:
            feats = _work_queue.get_nowait()
            _run_inference(feats)
    except queue.Empty:
        pass
    if monitoring:
        main.after(200, _poll_queue)          # reschedule every 200 ms


def _run_inference(feats):
    """Full pipeline: features -> encoder -> PCA -> RF + MLP -> log."""
    if encoder_model is None or pca is None or random_forest is None or mlp is None:
        return
    try:
        arr     = np.array(feats, dtype=float).reshape(1, -1)
        encoded = encoder_model.predict(arr, verbose=0)
        reduced = pca.transform(encoded)

        p_rf  = int(random_forest.predict(reduced)[0])
        p_mlp = int(mlp.predict(reduced)[0])

        rf_result  = "NO THREAT" if p_rf  == 0 else f"THREAT: {labels[min(p_rf,  len(labels)-1)]}"
        mlp_result = "NO THREAT" if p_mlp == 0 else f"THREAT: {labels[min(p_mlp, len(labels)-1)]}"

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        detection_log.append({'timestamp': ts, 'rf': rf_result, 'mlp': mlp_result})
        _refresh_log_widget()

    except Exception as e:
        print("Inference error:", e)


def _refresh_log_widget():
    """Redraws the log Text widget. Always called on the main thread."""
    log_text.config(state=NORMAL)
    log_text.delete('1.0', END)

    log_text.tag_config('ts',  foreground='#ffff00', font=('Courier', 10, 'bold'))
    log_text.tag_config('ok',  foreground='#00ff88', font=('Courier', 10))
    log_text.tag_config('bad', foreground='#ff4444', font=('Courier', 10, 'bold'))
    log_text.tag_config('sep', foreground='#336633')

    for entry in detection_log[-15:]:
        log_text.insert(END, f"  [{entry['timestamp']}]\n", 'ts')
        rf_tag  = 'bad' if 'THREAT' in entry['rf']  else 'ok'
        mlp_tag = 'bad' if 'THREAT' in entry['mlp'] else 'ok'
        log_text.insert(END, f"    RF  -> {entry['rf']}\n",  rf_tag)
        log_text.insert(END, f"    MLP -> {entry['mlp']}\n", mlp_tag)
        log_text.insert(END, "  " + "-" * 55 + "\n", 'sep')

    log_text.see(END)
    log_text.config(state=DISABLED)


# ── Start / Stop button ───────────────────────────────────────────────────────
def start_monitoring():
    global monitoring

    # FIX 5: check the actual objects, not the globals() dict
    if encoder_model is None:
        messagebox.showerror("Error", "Please run AutoEncoder first.")
        return
    if random_forest is None:
        messagebox.showerror("Error", "Please run Random Forest first.")
        return
    if mlp is None:
        messagebox.showerror("Error", "Please run MLP first.")
        return

    if not monitoring:
        monitoring = True
        monitor_button.config(text="Stop Monitoring", bg='red')

        # Simulated traffic thread (works without admin rights)
        threading.Thread(target=generate_simulated_traffic, daemon=True).start()

        # Real packet sniffer (needs root/admin; skipped if scapy unavailable)
        if SCAPY_OK:
            threading.Thread(
                target=sniff,
                kwargs={'prn': capture_packet, 'store': 0},
                daemon=True
            ).start()

        # FIX 4: start the main-thread queue poller
        main.after(200, _poll_queue)

        messagebox.showinfo("Monitoring", "Real-time threat detection STARTED!\n"
                                          "Entries will appear in the log below.")
    else:
        monitoring = False
        monitor_button.config(text="Start Monitoring", bg='green')
        messagebox.showinfo("Monitoring", "Real-time threat detection STOPPED.")


# ── Save log ──────────────────────────────────────────────────────────────────
def save_detection_log():
    if not detection_log:
        messagebox.showwarning("Warning", "No detection data to save yet.")
        return
    fname = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
    )
    if not fname:
        return
    try:
        with open(fname, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'rf', 'mlp'])
            writer.writeheader()
            writer.writerows(detection_log)
        messagebox.showinfo("Saved", f"Detection log saved to:\n{fname}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not save log:\n{e}")


# ── Clear log ─────────────────────────────────────────────────────────────────
def clear_detection_log():
    global detection_log
    detection_log = []
    log_text.config(state=NORMAL)
    log_text.delete('1.0', END)
    log_text.config(state=DISABLED)
    messagebox.showinfo("Cleared", "Detection log cleared.")


# =============================================================
#  ORIGINAL FUNCTIONS (same logic as the repo)
# =============================================================

def uploadDataset():
    global filename, dataset
    text.delete('1.0', END)
    filename = filedialog.askopenfilename(initialdir="Dataset")
    if not filename:
        return
    text.insert(END, filename + " loaded\n\n")
    dataset = pd.read_csv(filename)
    text.insert(END, "Dataset Values\n\n")
    text.insert(END, str(dataset.head()))
    text.update_idletasks()

    unique, count = np.unique(dataset['result'], return_counts=True)
    y_pos = np.arange(len(labels))
    plt.bar(y_pos, count)
    plt.xticks(y_pos, labels, rotation=90)
    plt.title("Various Cyber-Attacks Found in Dataset")
    plt.tight_layout()
    plt.show()


def preprocessing():
    text.delete('1.0', END)
    global dataset, scaler, X_train, X_test, y_train, y_test, X, Y

    dataset.fillna(0, inplace=True)
    scaler  = MinMaxScaler()
    data    = dataset.values
    X       = data[:, 0:data.shape[1] - 1]
    Y       = data[:, data.shape[1] - 1]

    indices = np.arange(X.shape[0])
    np.random.shuffle(indices)
    X = X[indices]
    Y = Y[indices]

    Y = to_categorical(Y)
    X = scaler.fit_transform(X)

    os.makedirs("model", exist_ok=True)
    with open('model/minmax.txt', 'wb') as f:
        pickle.dump(scaler, f)

    text.insert(END, "Dataset after feature normalization\n\n")
    text.insert(END, str(X) + "\n\n")
    text.insert(END, "Total records found in dataset: " + str(X.shape[0]) + "\n")
    text.insert(END, "Total features found in dataset: " + str(X.shape[1]) + "\n\n")

    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2)
    text.insert(END, "Dataset Train and Test Split\n\n")
    text.insert(END, "80% records for training: " + str(X_train.shape[0]) + "\n")
    text.insert(END, "20% records for testing : " + str(X_test.shape[0]) + "\n")


def calculateMetrics(algorithm, predict, y_test_arg):
    a = accuracy_score(y_test_arg, predict) * 100
    p = precision_score(y_test_arg, predict, average='macro', zero_division=1) * 100
    r = recall_score(y_test_arg,   predict, average='macro', zero_division=1) * 100
    f = f1_score(y_test_arg,       predict, average='macro', zero_division=1) * 100
    accuracy.append(a); precision.append(p); recall.append(r); fscore.append(f)
    text.insert(END, f"{algorithm} Accuracy : {a:.2f}%\n")
    text.insert(END, f"{algorithm} Precision: {p:.2f}%\n")
    text.insert(END, f"{algorithm} Recall   : {r:.2f}%\n")
    text.insert(END, f"{algorithm} FScore   : {f:.2f}%\n\n")


def runAutoEncoder():
    global autoencoder, accuracy, precision, recall, fscore

    if X is None:
        messagebox.showerror("Error", "Please preprocess the dataset first.")
        return

    text.delete('1.0', END)
    text.insert(END, "AutoEncoder training started... Please wait\n")
    text.update()

    accuracy = []; precision = []; recall = []; fscore = []
    os.makedirs("model", exist_ok=True)

    try:
        if os.path.exists("model/encoder_model.json"):
            text.insert(END, "Loading existing AutoEncoder model...\n"); text.update()
            with open('model/encoder_model.json') as jf:
                autoencoder = model_from_json(jf.read())
            autoencoder.load_weights("model/encoder_model.weights.h5")
        else:
            text.insert(END, "Training new AutoEncoder model...\n"); text.update()
            inp     = keras.Input(shape=(X.shape[1],))
            noisy   = layers.GaussianNoise(0.3)(inp)
            encoded = layers.Dense(32, activation='relu')(noisy)
            encoded = layers.Dropout(0.5)(encoded)
            decoded = layers.Dense(y_train.shape[1], activation='softmax')(encoded)
            autoencoder = keras.Model(inp, decoded)
            autoencoder.compile(optimizer='adam',
                                loss='categorical_crossentropy',
                                metrics=['accuracy'])
            autoencoder.fit(X_train, y_train, epochs=5, batch_size=128,
                            shuffle=True, validation_data=(X_test, y_test), verbose=1)
            autoencoder.save_weights('model/encoder_model.weights.h5')
            with open("model/encoder_model.json", "w") as jf:
                jf.write(autoencoder.to_json())

        text.insert(END, "\nAutoEncoder Model Ready!\n"); text.update()
        predict = np.argmax(autoencoder.predict(X_test), axis=1)
        testY   = np.argmax(y_test, axis=1)
        calculateMetrics("AutoEncoder", predict, testY)

    except Exception as e:
        messagebox.showerror("AutoEncoder Error", str(e))


def runRandomForest():
    global random_forest, encoder_model, vector, pca
    global X_train, X_test, y_train, y_test

    # FIX 6: missing `return` in original – execution continued with None autoencoder
    if autoencoder is None:
        messagebox.showerror("Error", "Please run AutoEncoder first.")
        return

    encoder_model = Model(autoencoder.input, autoencoder.layers[1].output)
    vector = encoder_model.predict(X)
    pca    = PCA(n_components=7)
    vector = pca.fit_transform(vector)

    Y1 = np.argmax(Y, axis=1)
    X_train, X_test, y_train, y_test = train_test_split(vector, Y1, test_size=0.2)

    random_forest = RandomForestClassifier()
    random_forest.fit(X_train, y_train)
    predict = random_forest.predict(X_test)

    text.insert(END, "Random Forest Trained\n")
    calculateMetrics("Random Forest", predict, y_test)


def runMLP():
    global mlp, encoder_model, vector, pca
    global X_train, X_test, y_train, y_test

    # FIX 6 (same): missing `return`
    if autoencoder is None:
        messagebox.showerror("Error", "Please run AutoEncoder first.")
        return

    # reuse encoder_model & pca already built by runRandomForest if available
    if encoder_model is None:
        encoder_model = Model(autoencoder.input, autoencoder.layers[1].output)
        vector = encoder_model.predict(X)
        pca    = PCA(n_components=7)
        vector = pca.fit_transform(vector)
    else:
        vector = encoder_model.predict(X)
        vector = pca.transform(vector)

    Y1 = np.argmax(Y, axis=1)
    X_train, X_test, y_train, y_test = train_test_split(vector, Y1, test_size=0.2)

    mlp = MLPClassifier()
    mlp.fit(X_train, y_train)
    predict = mlp.predict(X_test)

    text.insert(END, "Multilayer Perceptron Trained\n")
    calculateMetrics("MLP", predict, y_test)


def attackAttributeDetection():
    text.delete('1.0', END)
    if encoder_model is None or random_forest is None or mlp is None:
        messagebox.showerror("Error", "Please run all algorithms first.")
        return

    fname = filedialog.askopenfilename(initialdir="Dataset")
    if not fname:
        return
    ds     = pd.read_csv(fname)
    ds.fillna(0, inplace=True)
    values = ds.values
    temp   = scaler.transform(values)

    test_vector = encoder_model.predict(temp)
    test_vector = pca.transform(test_vector)
    predict_rf  = random_forest.predict(test_vector)
    predict_mlp = mlp.predict(test_vector)

    for i in range(len(test_vector)):
        rf_r  = "NO THREAT DETECTED" if predict_rf[i]  == 0 else \
                f"THREAT DETECTED: {labels[min(int(predict_rf[i]),  len(labels)-1)]}"
        mlp_r = "NO THREAT DETECTED" if predict_mlp[i] == 0 else \
                f"THREAT DETECTED: {labels[min(int(predict_mlp[i]), len(labels)-1)]}"
        text.insert(END,
            f"New Test Data : {str(values[i])}\n"
            f"RF Result : {rf_r}\n"
            f"MLP Result: {mlp_r}\n\n")


def graph(metric):
    mapping = {"Accuracy": accuracy, "Precision": precision,
               "Recall": recall, "F1 Score": fscore}
    df = pd.DataFrame({'Algorithms': ['AutoEncoder', 'Random Forest', 'MLP'],
                       metric: mapping[metric]})
    df.plot(x='Algorithms', y=metric, kind='bar', legend=False)
    plt.title(f"{metric} Comparison")
    plt.ylabel(metric)
    plt.tight_layout()
    plt.show()


def showGraphSelection():
    w = Toplevel(main)
    w.title("Select Metric to Plot")
    Label(w, text="Select Metric:", font=('times', 14, 'bold')).pack(pady=10)
    for m in ["Accuracy", "Precision", "Recall", "F1 Score"]:
        Button(w, text=m, command=lambda m=m: graph(m),
               font=('times', 12, 'bold')).pack(pady=5)


def comparisonTable():
    precautions = {
        "Phishing":
            "Implement email filtering, educate users, enable MFA.",
        "Denial of Service (DoS)":
            "Rate-limiting, firewalls, IDS/IPS, load balancers.",
        "Distributed Denial of Service (DDoS)":
            "DDoS protection services, CDNs, response plans.",
        "Man-in-the-Middle (MITM)":
            "SSL/TLS, certificate pinning, secure connections.",
        "SQL Injection":
            "Parameterized queries, WAF, sanitize inputs.",
        "Cross-Site Scripting (XSS)":
            "Sanitize inputs, Content Security Policy, output encoding.",
        "Zero-Day Exploit":
            "Keep software patched, use IDS, monitor network activity.",
        "Brute Force Attack":
            "Account lockout, CAPTCHA, strong passwords, MFA.",
    }
    rows = "".join(
        f"<tr><td><b>{a}</b></td><td>{p}</td></tr>"
        for a, p in precautions.items()
    )
    html = f"""<!DOCTYPE html><html><head><title>CyberShield Results</title>
<style>
body{{font-family:Arial,sans-serif;background:linear-gradient(to right,#0066ff,#33ccff);
     text-align:center;color:#fff}}
h2{{color:#ffcc00;text-shadow:2px 2px 4px #000}}
table{{width:82%;margin:20px auto;border-collapse:collapse;
       background:rgba(255,255,255,.92);color:#000;
       border-radius:10px;overflow:hidden;box-shadow:0 0 12px rgba(0,0,0,.4)}}
th{{background:#ff6600;color:#fff;padding:10px}}
td{{border:1px solid #aaa;padding:9px;text-align:center}}
tr:nth-child(even){{background:#f5f5f5}}tr:hover{{background:#fffacc}}
</style></head><body>
<h2>Performance Comparison</h2>
<table>
<tr><th>Algorithm</th><th>Accuracy (%)</th><th>Precision (%)</th>
    <th>Recall (%)</th><th>F1 Score (%)</th></tr>
<tr><td>AutoEncoder</td>
    <td>{accuracy[0]:.2f}</td><td>{precision[0]:.2f}</td>
    <td>{recall[0]:.2f}</td><td>{fscore[0]:.2f}</td></tr>
<tr><td>Random Forest</td>
    <td>{accuracy[1]:.2f}</td><td>{precision[1]:.2f}</td>
    <td>{recall[1]:.2f}</td><td>{fscore[1]:.2f}</td></tr>
<tr><td>MLP</td>
    <td>{accuracy[2]:.2f}</td><td>{precision[2]:.2f}</td>
    <td>{recall[2]:.2f}</td><td>{fscore[2]:.2f}</td></tr>
</table>
<h2>Precautionary Measures</h2>
<table><tr><th>Attack Type</th><th>Recommended Action</th></tr>
{rows}</table>
</body></html>"""
    with open("table.html", "w") as f:
        f.write(html)
    webbrowser.open("table.html", new=2)


# =============================================================
#  GUI LAYOUT  —  all widgets fit inside 1300 x 950 px
# =============================================================
# Y positions (nothing goes below y=910):
#   5   – title          (~70 px tall)
#   80  – output text    (height=13 lines ≈ 210 px)
#   300 – btn row 1      (~35 px)
#   345 – btn row 2      (~35 px)
#   395 – log header     (~25 px)
#   425 – log text box   (height=8 lines ≈ 145 px)
#   580 – 3 action btns  (~40 px)
# =============================================================

# bg_img    = Image.open("image.jpg").resize((1300, 950), Image.LANCZOS)
# bg_img_tk = ImageTk.PhotoImage(bg_img)
# bg_label  = Label(main, image=bg_img_tk)
# bg_label.place(x=0, y=0, relwidth=1, relheight=1)

# main.geometry("1300x950")    

# font  = ('times', 14, 'bold')
# font1 = ('times', 12, 'bold')
# font2 = ('times', 11, 'bold')

# ── Title ─────────────────────────────────────────────────────── y=5
# title = Label(main,
#               text='REAL-TIME CYBER THREAT DETECTION SYSTEM\n'
#                    'Using Autoencoder, Random Forest and MLP',
#               bg='greenyellow', fg='dodger blue', font=font,
#               height=2, width=140)
# title.place(x=0, y=5)

# # ── Main output text box ──────────────────────────────────────── y=75
# text = Text(main, height=13, width=152, font=font1)
# scroll = Scrollbar(main, orient=VERTICAL, command=text.yview)
# text.configure(yscrollcommand=scroll.set)
# text.place(x=10, y=75)
# scroll.place(x=1281, y=75, height=215)

# # ── Algorithm buttons – Row 1 ─────────────────────────────────── y=300
# Button(main, text="Upload Dataset",
#        command=uploadDataset, font=font2).place(x=10, y=300)

# Button(main, text="Preprocess Dataset",
#        command=preprocessing, font=font2).place(x=200, y=300)

# Button(main, text="Run AutoEncoder",
#        command=lambda: threading.Thread(
#            target=runAutoEncoder, daemon=True).start(),
#        font=font2).place(x=420, y=300)

# Button(main, text="Run Random Forest",
#        command=runRandomForest, font=font2).place(x=620, y=300)

# Button(main, text="Run MLP",
#        command=runMLP, font=font2).place(x=850, y=300)

# # ── Algorithm buttons – Row 2 ─────────────────────────────────── y=345
# Button(main, text="Detection & Attribute Attack Type",
#        command=attackAttributeDetection, font=font2).place(x=10, y=345)

# Button(main, text="Comparison Graph",
#        command=showGraphSelection, font=font2).place(x=420, y=345)

# Button(main, text="Comparison Table",
#        command=comparisonTable, font=font2).place(x=700, y=345)

# # ── Real-Time Detection Log header ────────────────────────────── y=395
# Label(main,
#       text="  ⚡ Real-Time Detection Log  —  threats show in RED, safe traffic in GREEN",
#       bg='#001133', fg='#00ccff',
#       font=('times', 11, 'bold'),
#       anchor='w', width=140).place(x=10, y=395)

# # ── Log text box ──────────────────────────────────────────────── y=425
# log_text = Text(main, height=8, width=152,
#                 font=('Courier', 10),
#                 bg='#050510', fg='#00ff88',
#                 insertbackground='white',
#                 relief=SUNKEN, bd=2,
#                 state=DISABLED)
# log_scroll = Scrollbar(main, orient=VERTICAL, command=log_text.yview)
# log_text.configure(yscrollcommand=log_scroll.set)
# log_text.place(x=10, y=425)
# log_scroll.place(x=1281, y=425, height=145)

# # ── Three action buttons ──────────────────────────────────────── y=580
# monitor_button = Button(main,
#                         text="▶  Start Monitoring",
#                         command=start_monitoring,
#                         font=('times', 12, 'bold'),
#                         bg='#007700', fg='white',
#                         width=20, relief=RAISED, bd=3)
# monitor_button.place(x=10, y=580)

# Button(main,
#        text="💾  Save Detection Log",
#        command=save_detection_log,
#        font=('times', 12, 'bold'),
#        bg='#0055bb', fg='white',
#        width=20, relief=RAISED, bd=3).place(x=280, y=580)

# Button(main,
#        text="🗑  Clear Log",
#        command=clear_detection_log,
#        font=('times', 12, 'bold'),
#        bg='#994400', fg='white',
#        width=14, relief=RAISED, bd=3).place(x=550, y=580)

# main.mainloop()


# =============================================================
#  MODERN UI DESIGN
# =============================================================

main.geometry("1300x900")
main.configure(bg="#0b132b")

title = Label(main,
              text="CYBERSHIELD - REAL-TIME CYBER THREAT DETECTION",
              bg="#1c2541", fg="#5bc0be",
              font=('times', 18, 'bold'),
              height=2)
title.pack(fill=X)

# ================= MAIN OUTPUT =================
frame_top = Frame(main, bg="#0b132b")
frame_top.pack(pady=10)

text = Text(frame_top, height=12, width=140,
            font=('times', 11),
            bg="#020617", fg="#00ffcc",
            insertbackground="white")
text.pack(side=LEFT)

scroll = Scrollbar(frame_top, command=text.yview)
scroll.pack(side=RIGHT, fill=Y)
text.config(yscrollcommand=scroll.set)

# ================= BUTTONS =================
frame_buttons = Frame(main, bg="#0b132b")
frame_buttons.pack(pady=10)

Button(frame_buttons, text="Upload Dataset", command=uploadDataset,
       width=18, bg="#3a86ff", fg="white").grid(row=0, column=0, padx=10, pady=5)

Button(frame_buttons, text="Preprocess Dataset", command=preprocessing,
       width=18, bg="#3a86ff", fg="white").grid(row=0, column=1, padx=10)

Button(frame_buttons, text="Run AutoEncoder",
       command=lambda: threading.Thread(target=runAutoEncoder, daemon=True).start(),
       width=18, bg="#8338ec", fg="white").grid(row=0, column=2, padx=10)

Button(frame_buttons, text="Run Random Forest",
       command=runRandomForest,
       width=18, bg="#ff006e", fg="white").grid(row=0, column=3, padx=10)

Button(frame_buttons, text="Run MLP",
       command=runMLP,
       width=18, bg="#ff006e", fg="white").grid(row=0, column=4, padx=10)

Button(frame_buttons, text="Attack Detection",
       command=attackAttributeDetection,
       width=18, bg="#fb5607", fg="white").grid(row=1, column=0, pady=10)

Button(frame_buttons, text="Comparison Graph",
       command=showGraphSelection,
       width=18, bg="#fb5607", fg="white").grid(row=1, column=1)

Button(frame_buttons, text="Comparison Table",
       command=comparisonTable,
       width=18, bg="#fb5607", fg="white").grid(row=1, column=2)

# ================= REAL-TIME LOG =================
log_label = Label(main,
                  text="⚡ Real-Time Detection Log",
                  bg="#1c2541", fg="#00ffcc",
                  font=('times', 14, 'bold'))
log_label.pack(fill=X, pady=5)

frame_log = Frame(main)
frame_log.pack()

log_text = Text(frame_log, height=10, width=140,
                font=('Courier', 10),
                bg="#020617", fg="#00ff88",
                insertbackground="white",
                state=DISABLED)
log_text.pack(side=LEFT)

log_scroll = Scrollbar(frame_log, command=log_text.yview)
log_scroll.pack(side=RIGHT, fill=Y)
log_text.config(yscrollcommand=log_scroll.set)

# ================= CONTROL BUTTONS =================
frame_controls = Frame(main, bg="#0b132b")
frame_controls.pack(pady=15)

monitor_button = Button(frame_controls,
                        text="▶ Start Monitoring",
                        command=start_monitoring,
                        bg="#06d6a0", fg="black",
                        width=20, font=('times', 12, 'bold'))
monitor_button.grid(row=0, column=0, padx=20)

Button(frame_controls,
       text="💾 Save Log",
       command=save_detection_log,
       bg="#118ab2", fg="white",
       width=20, font=('times', 12, 'bold')).grid(row=0, column=1, padx=20)

Button(frame_controls,
       text="🗑 Clear Log",
       command=clear_detection_log,
       bg="#ef476f", fg="white",
       width=15, font=('times', 12, 'bold')).grid(row=0, column=2, padx=20)

main.mainloop()