import tkinter as tk
from tkinter import ttk
import hashlib
import time
import threading
import random
import base58

# ------------------ Funções para gerar endereço Bitcoin ------------------
def generate_private_key():
    return ''.join(random.choices('0123456789ABCDEF', k=64))

def generate_public_key(private_key):
    return hashlib.sha256(private_key.encode()).hexdigest()

def generate_address(public_key):
    sha256_hash = hashlib.sha256(public_key.encode()).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_hash).digest()
    address = base58.b58encode(b'\x00' + ripemd160).decode()
    return address

def generate_bitcoin_address():
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    return generate_address(public_key)

# ------------------ Estrutura do Bloco ------------------
class Block:
    def __init__(self, index, previous_hash, transactions, nonce=0):
        self.index = index
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.transactions}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        target = '0' * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()

# ------------------ Blockchain ------------------
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 3
        self.mempool = []

    def create_genesis_block(self):
        return Block(0, "0", ["Genesis Block"])

    def get_latest_block(self):
        return self.chain[-1]

    def add_transaction(self, sender, receiver, amount):
        transaction = f"{sender} → {receiver}: {amount} BTC"
        self.mempool.append(transaction)

    def mine_pending_transactions(self):
        if not self.mempool:
            return None
        new_block = Block(len(self.chain), self.get_latest_block().hash, self.mempool[:])
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        self.mempool.clear()
        return new_block

# ------------------ Interface Gráfica ------------------
class BlockchainGUI:
    def __init__(self, master):
        self.master = master
        master.title("Simulador de Blockchain")
        master.geometry("800x700")
        master.configure(bg="#2E2E2E")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Montserrat", 11, "bold"), borderwidth=0, padding=5)
        style.configure("Add.TButton", background="#5CB85C", foreground="white")
        style.configure("Mine.TButton", background="#0275D8", foreground="white")
        style.configure("Gen.TButton", background="#D9534F", foreground="white")
        style.configure("Clear.TButton", background="#D9534F", foreground="white")

        self.blockchain = Blockchain()
        self.addresses = []

        # Frame principal dividido em dois
        top_frame = tk.Frame(master, bg="#2E2E2E")
        top_frame.pack(fill="both", expand=False, padx=10, pady=10)

        left_frame = tk.Frame(top_frame, bg="#2E2E2E")
        left_frame.pack(side="left", fill="both", expand=True, padx=5)

        right_frame = tk.Frame(top_frame, bg="#2E2E2E")
        right_frame.pack(side="right", fill="both", expand=True, padx=5)

        # ---------- LADO ESQUERDO: Gerador de Endereços ----------
        self.generate_address_button = ttk.Button(left_frame, text="Gerar Endereço Bitcoin", style="Gen.TButton", command=self.generate_address)
        self.generate_address_button.pack(pady=5)

        self.address_listbox = tk.Listbox(left_frame, height=8, width=40, bg="#1E1E1E", fg="white")
        self.address_listbox.pack(pady=5)

        self.copy_button = ttk.Button(left_frame, text="Copiar Endereço", width=20, command=self.copy_address)
        self.copy_button.pack(pady=2)

        self.clear_button = ttk.Button(left_frame, text="Limpar Endereços", width=20, style="Clear.TButton", command=self.clear_addresses)
        self.clear_button.pack(pady=2)

        # ---------- LADO DIREITO: Transações ----------
        self.create_label(right_frame, "Remetente:")
        self.sender_entry = ttk.Entry(right_frame, width=35)
        self.sender_entry.pack(pady=2)

        self.create_label(right_frame, "Destinatário:")
        self.receiver_entry = ttk.Entry(right_frame, width=35)
        self.receiver_entry.pack(pady=2)

        self.create_label(right_frame, "Quantidade (BTC):")
        self.amount_entry = ttk.Entry(right_frame, width=35)
        self.amount_entry.pack(pady=5)

        self.add_button = ttk.Button(right_frame, text="Adicionar Transação", style="Add.TButton", command=self.add_transaction)
        self.add_button.pack(pady=2)

        self.mine_button = ttk.Button(right_frame, text="Minerar Bloco", style="Mine.TButton", command=self.mine_block)
        self.mine_button.pack(pady=10)

        # ---------- ÁREA DE SAÍDA INFERIOR ----------
        self.output_frame = tk.Frame(master)
        self.output_frame.pack(pady=10, fill="both", expand=True, padx=10)

        self.output = tk.Text(self.output_frame, height=15, bg="#1E1E1E", fg="white", font=("Courier", 10))
        self.output.pack(side="left", fill="both", expand=True)

        self.scrollbar = ttk.Scrollbar(self.output_frame, command=self.output.yview)
        self.output.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")

        self.refresh_output()

    def create_label(self, frame, text):
        label = ttk.Label(frame, text=text, foreground="white", background="#2E2E2E", font=("Segoe UI", 10))
        label.pack()

    def generate_address(self):
        new_address = generate_bitcoin_address()
        self.addresses.append(new_address)
        self.address_listbox.insert(tk.END, new_address)

    def copy_address(self):
        selected = self.address_listbox.curselection()
        if selected:
            address = self.address_listbox.get(selected[0])
            self.master.clipboard_clear()
            self.master.clipboard_append(address)
            self.master.update()
            # self.output.insert(tk.END, f"[✓] Endereço copiado: {address}\n")  # Removido para não exibir no output

    def clear_addresses(self):
        self.address_listbox.delete(0, tk.END)

    def add_transaction(self):
        sender = self.sender_entry.get()
        receiver = self.receiver_entry.get()
        amount = self.amount_entry.get()
        if sender and receiver and amount:
            try:
                float(amount)
                self.blockchain.add_transaction(sender, receiver, amount)
                transaction_msg = f"[+] Transação adicionada ao mempool: {sender} → {receiver} ({amount} BTC)\n"
                self.output.insert(tk.END, transaction_msg)
                self.output.see(tk.END)  # Faz o scroll automático até a linha adicionada
                self.sender_entry.delete(0, tk.END)
                self.receiver_entry.delete(0, tk.END)
                self.amount_entry.delete(0, tk.END)
            except ValueError:
                self.output.insert(tk.END, "[Erro] Quantidade inválida!\n")

    def mine_block(self):
        def mining():
            new_block = self.blockchain.mine_pending_transactions()
            self.refresh_output()
            if new_block:
                self.output.insert(tk.END, f"\n[✓] Bloco {new_block.index} minerado com sucesso!\n")
        threading.Thread(target=mining).start()

    def refresh_output(self):
        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, "⛓️ Blockchain Atual:\n\n")
        for block in self.blockchain.chain:
            self.output.insert(tk.END, f"🧱 Bloco {block.index}\n")
            self.output.insert(tk.END, f"⏱️ Timestamp: {block.timestamp}\n")
            self.output.insert(tk.END, f"🔢 Nonce: {block.nonce}\n")
            self.output.insert(tk.END, f"🔗 Hash: {block.hash}\n")
            self.output.insert(tk.END, f"↩️ Hash Anterior: {block.previous_hash}\n")
            self.output.insert(tk.END, "📦 Transações:\n")
            for tx in block.transactions:
                self.output.insert(tk.END, f"  - {tx}\n")
            self.output.insert(tk.END, "\n" + "-"*60 + "\n\n")

# ------------------ Execução ------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = BlockchainGUI(root)
    root.mainloop()
