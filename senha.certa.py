import tkinter as tk
from tkinter import messagebox
import re
from datetime import datetime

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Gerenciador de Senhas")
        self.master.geometry("400x500")
        self.master.config(bg="#f0f0f0")

        # Armazenar dados do usuário
        self.user_data = {}
        self.password_history = {}  # Armazenar as últimas 10 senhas por CPF

        # Menu
        self.menubar = tk.Menu(master)
        self.file_menu = tk.Menu(self.menubar, tearoff=0)
        self.file_menu.add_command(label="Sair", command=master.quit)
        self.menubar.add_cascade(label="Arquivo", menu=self.file_menu)
        self.master.config(menu=self.menubar)

        # Label para o título
        self.title_label = tk.Label(master, text="Cadastro de Senha", font=("Arial", 16, "bold"), bg="#f0f0f0")
        self.title_label.pack(pady=10)

        # Campo para o nome de usuário
        self.username_label = tk.Label(master, text="Nome de Usuário:", bg="#f0f0f0")
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(master, width=30)
        self.username_entry.pack(pady=5)

        # Campo para o CPF
        self.cpf_label = tk.Label(master, text="CPF (somente números):", bg="#f0f0f0")
        self.cpf_label.pack(pady=5)
        self.cpf_entry = tk.Entry(master, width=30)
        self.cpf_entry.pack(pady=5)

        # Campo para a senha
        self.password_label = tk.Label(master, text="Senha:", bg="#f0f0f0")
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(master, show="*", width=30)
        self.password_entry.pack(pady=5)

        # Botão para cadastrar
        self.register_button = tk.Button(master, text="Cadastrar", command=self.register_password, bg="#4CAF50", fg="white")
        self.register_button.pack(pady=20)

        # Botão para ver senha pelo CPF
        self.view_button = tk.Button(master, text="Ver Senha pelo CPF", command=self.view_password_by_cpf, bg="#2196F3", fg="white")
        self.view_button.pack(pady=10)

        # Botão para sair do modo cheio
        self.fullscreen_button = tk.Button(master, text="Ativar/Desativar Tela Cheia", command=self.toggle_fullscreen, bg="#FF5722", fg="white")
        self.fullscreen_button.pack(pady=10)

        # Mensagem de status
        self.status_message = tk.StringVar()
        self.status_label = tk.Label(master, textvariable=self.status_message, bg="#f0f0f0")
        self.status_label.pack(pady=5)

        self.is_fullscreen = False  # Flag para controlar o modo de tela cheia

    def toggle_fullscreen(self):
        """Alterna entre o modo de tela cheia e o modo janela."""
        self.is_fullscreen = not self.is_fullscreen
        self.master.attributes('-fullscreen', self.is_fullscreen)

    def validate_cpf(self, cpf):
        # Regex para validar o CPF (somente números e 11 dígitos)
        return re.match(r'^\d{11}$', cpf) is not None

    def validate_password(self, password, cpf):
        # Verifica se a senha atende aos critérios
        if len(password) < 12:
            return "A senha deve ter pelo menos 12 caracteres."
        if not re.search(r'[A-Z]', password):
            return "A senha deve conter pelo menos uma letra maiúscula."
        if not re.search(r'[a-z]', password):
            return "A senha deve conter pelo menos uma letra minúscula."
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return "A senha deve conter pelo menos um caractere especial."
        if self.is_sequential(password):
            return "A senha não pode ser sequencial."
        if self.contains_common_word(password):
            return "A senha não pode formar palavras comuns."
        if self.contains_personal_dates(password):
            return "A senha não pode conter datas pessoais."
        if self.is_reused_password(cpf, password):
            return "A senha não pode ser uma das últimas 10 senhas usadas."

        return True

    def is_sequential(self, password):
        # Verifica se a senha é sequencial
        sequences = ['0123456789', 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']
        for seq in sequences:
            if any(seq[i:i+3] in password for i in range(len(seq) - 2)):
                return True
        return False

    def contains_common_word(self, password):
        # Lista de palavras comuns
        common_words = ["senha", "123456", "qwerty", "admin", "welcome"]
        return any(word in password.lower() for word in common_words)

    def contains_personal_dates(self, password):
        # Verifica se a senha contém datas pessoais (simples, ex: "19032022")
        return re.search(r'\b\d{2}\/\d{2}\/\d{4}\b', password) is not None

    def is_reused_password(self, cpf, password):
        # Verifica se a senha foi reutilizada
        if cpf in self.password_history:
            if password in self.password_history[cpf]:
                return True
        return False

    def register_password(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        cpf = self.cpf_entry.get()

        # Valida se os campos não estão vazios
        if not username or not password or not cpf:
            messagebox.showwarning("Aviso", "Por favor, preencha todos os campos.")
            return
        
        # Valida o CPF
        if not self.validate_cpf(cpf):
            messagebox.showwarning("Aviso", "CPF inválido. Deve conter 11 dígitos numéricos.")
            return

        # Valida a senha
        password_validation = self.validate_password(password, cpf)
        if password_validation != True:
            messagebox.showwarning("Aviso", password_validation)
            return

        # Cadastra a senha
        self.user_data[cpf] = {'username': username, 'password': password, 'last_updated': datetime.now()}
        
        # Armazena as últimas 10 senhas usadas
        if cpf not in self.password_history:
            self.password_history[cpf] = []
        self.password_history[cpf].append(password)
        if len(self.password_history[cpf]) > 10:
            self.password_history[cpf].pop(0)  # Remove a senha mais antiga

        # Limpar campos após cadastro
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.cpf_entry.delete(0, tk.END)

        # Exibir mensagem de sucesso
        self.status_message.set(f"Senha cadastrada para {username} com sucesso!")

    def view_password_by_cpf(self):
        cpf = self.cpf_entry.get()

        # Valida o CPF
        if not self.validate_cpf(cpf):
            messagebox.showwarning("Aviso", "CPF inválido. Deve conter 11 dígitos numéricos.")
            return

        # Verifica se o CPF está cadastrado
        if cpf in self.user_data:
            user_info = self.user_data[cpf]
            messagebox.showinfo("Senha Encontrada", f"Usuário: {user_info['username']}\nSenha: {user_info['password']}")
        else:
            messagebox.showinfo("Senha Não Encontrada", "Nenhum usuário encontrado para esse CPF.")

# Execução da aplicação
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
