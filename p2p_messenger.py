import socket
import threading
import json
import time
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import uuid

class P2PMessenger:
    def __init__(self):
        # Генерируем уникальный ID для пользователя
        self.user_id = str(uuid.uuid4())[:8]
        self.username = f"User_{self.user_id}"
        self.users = {}  # Словарь онлайн-пользователей: {username: (ip, port)}
        self.running = True
        self.local_ip = "127.0.0.1"
        
        # Настройки сети
        self.broadcast_port = 9999  # Порт для широковещательных сообщений
        self.message_port = 10000   # Порт для личных сообщений
        
        # GUI
        self.root = tk.Tk()
        self.setup_gui()
        
    def get_all_ips(self):
        """Получаем все IP адреса компьютера"""
        ip_list = []
        
        # Пробуем получить IP через hostname
        try:
            hostname = socket.gethostname()
            ip_list = socket.gethostbyname_ex(hostname)[2]
            ip_list = [ip for ip in ip_list if ip != '127.0.0.1' and not ip.startswith('169.254.')]
        except:
            pass
        
        # Пробуем получить IP через подключение к внешнему серверу
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            external_ip = s.getsockname()[0]
            s.close()
            if external_ip not in ip_list and external_ip != '127.0.0.1':
                ip_list.append(external_ip)
        except:
            pass
        
        # Если ничего не нашли, пробуем получить через создание временного сокета
        if not ip_list:
            try:
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                temp_socket.bind(('', 0))
                temp_socket.connect(("10.255.255.255", 1))
                local_ip = temp_socket.getsockname()[0]
                temp_socket.close()
                if local_ip not in ip_list and local_ip != '127.0.0.1':
                    ip_list.append(local_ip)
            except:
                pass
        
        # Если всё ещё пусто, добавляем localhost
        if not ip_list:
            ip_list = ["127.0.0.1"]
        
        return list(set(ip_list))  # Убираем дубликаты
        
    def choose_ip_dialog(self):
        """Диалог выбора IP адреса"""
        ip_list = self.get_all_ips()
        
        if len(ip_list) == 1:
            return ip_list[0]
        
        # Создаем окно выбора IP
        dialog = tk.Toplevel(self.root)
        dialog.title("Выбор сетевого интерфейса")
        dialog.geometry("350x250")
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Выберите IP адрес для подключения:", 
                font=('Arial', 10)).pack(pady=10)
        
        selected_ip = tk.StringVar(value=ip_list[0])
        
        frame = tk.Frame(dialog)
        frame.pack(pady=10)
        
        for ip in ip_list:
            tk.Radiobutton(frame, text=ip, variable=selected_ip, 
                          value=ip, font=('Arial', 9)).pack(anchor=tk.W, padx=20, pady=5)
        
        def on_ok():
            dialog.grab_release()
            dialog.destroy()
        
        tk.Button(dialog, text="OK", command=on_ok, width=15, 
                 bg='#4CAF50', fg='white').pack(pady=20)
        
        dialog.focus_set()
        self.root.wait_window(dialog)
        return selected_ip.get()
        
    def setup_sockets(self, bind_ip):
        """Настройка сокетов с выбранным IP"""
        self.local_ip = bind_ip
        
        # Закрываем старые сокеты если они есть
        if hasattr(self, 'broadcast_socket'):
            try:
                self.broadcast_socket.close()
            except:
                pass
                
        if hasattr(self, 'message_socket'):
            try:
                self.message_socket.close()
            except:
                pass
        
        # Создаем новые сокеты
        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.broadcast_socket.settimeout(0.5)
        
        self.message_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.message_socket.bind((bind_ip, self.message_port))
        self.message_socket.settimeout(0.5)
        
    def setup_gui(self):
        self.root.title(f"P2P Messenger - {self.username}")
        self.root.geometry("850x650")
        
        # Фрейм для информации и настроек
        info_frame = tk.Frame(self.root, bg='#2c3e50')
        info_frame.pack(side=tk.TOP, fill=tk.X)
        
        # Информация о текущем IP
        self.ip_label = tk.Label(info_frame, 
                                text=f"IP: {self.local_ip}", 
                                bg='#2c3e50', fg='white',
                                font=('Arial', 10, 'bold'))
        self.ip_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Имя пользователя
        self.name_label = tk.Label(info_frame, 
                                  text=f"Имя: {self.username}", 
                                  bg='#2c3e50', fg='white',
                                  font=('Arial', 10))
        self.name_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Кнопка смены IP
        tk.Button(info_frame, text="🔄 Сменить IP", 
                 command=self.change_ip,
                 bg='#3498db', fg='white',
                 font=('Arial', 9)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Кнопка смены имени
        tk.Button(info_frame, text="✏️ Сменить имя", 
                 command=self.change_username,
                 bg='#e74c3c', fg='white',
                 font=('Arial', 9)).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Основной фрейм
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Фрейм для списка пользователей
        users_frame = tk.Frame(main_frame, width=250, bg='#34495e')
        users_frame.pack(side=tk.LEFT, fill=tk.Y)
        users_frame.pack_propagate(False)
        
        # Заголовок списка пользователей
        tk.Label(users_frame, text="👥 Онлайн пользователи:", 
                bg='#34495e', fg='white',
                font=('Arial', 11, 'bold')).pack(pady=10)
        
        # Список пользователей
        self.users_listbox = tk.Listbox(users_frame, bg='white',
                                       font=('Arial', 10),
                                       selectbackground='#3498db',
                                       selectforeground='white')
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Статус
        self.status_label = tk.Label(users_frame, 
                                    text="Ожидание подключения...",
                                    bg='#34495e', fg='#ecf0f1',
                                    font=('Arial', 9))
        self.status_label.pack(pady=5)
        
        # Фрейм для чата
        chat_frame = tk.Frame(main_frame)
        chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Область чата
        self.chat_area = scrolledtext.ScrolledText(chat_frame, 
                                                  state='disabled',
                                                  bg='#ecf0f1',
                                                  font=('Arial', 10))
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Фрейм для ввода сообщения
        input_frame = tk.Frame(chat_frame, bg='#bdc3c7')
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Выбор типа сообщения
        self.message_type = tk.StringVar(value="general")
        
        type_frame = tk.Frame(input_frame, bg='#bdc3c7')
        type_frame.pack(side=tk.LEFT, padx=5)
        
        tk.Radiobutton(type_frame, text="💬 Общий чат", 
                      variable=self.message_type,
                      value="general",
                      bg='#bdc3c7',
                      font=('Arial', 9)).pack(side=tk.LEFT)
        
        tk.Radiobutton(type_frame, text="🔒 ЛС", 
                      variable=self.message_type,
                      value="private",
                      bg='#bdc3c7',
                      font=('Arial', 9)).pack(side=tk.LEFT, padx=10)
        
        # Поле ввода сообщения
        self.message_entry = tk.Entry(input_frame, 
                                     font=('Arial', 10),
                                     bg='white')
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind("<Return>", self.send_message_event)
        
        # Кнопка отправки
        tk.Button(input_frame, text="📤 Отправить", 
                 command=self.send_message,
                 bg='#27ae60', fg='white',
                 font=('Arial', 10, 'bold'),
                 width=12).pack(side=tk.RIGHT, padx=5)
        
    def change_ip(self):
        """Смена IP адреса для подключения"""
        selected_ip = self.choose_ip_dialog()
        if selected_ip and selected_ip != self.local_ip:
            # Перезапускаем сокеты с новым IP
            self.setup_sockets(selected_ip)
            self.ip_label.config(text=f"IP: {self.local_ip}")
            
            # Очищаем список пользователей
            self.users.clear()
            self.update_users_list()
            
            # Отправляем новое presence-сообщение
            self.broadcast_presence()
            self.display_message(f"[🔧 Система] Переключился на IP: {self.local_ip}")
            self.status_label.config(text=f"Подключен с IP: {self.local_ip}")
        
    def change_username(self):
        new_name = simpledialog.askstring("Смена имени", 
                                         "Введите новое имя:",
                                         parent=self.root)
        if new_name and new_name.strip():
            self.username = new_name.strip()
            self.root.title(f"P2P Messenger - {self.username}")
            self.name_label.config(text=f"Имя: {self.username}")
            self.broadcast_presence()
            self.display_message(f"[🔧 Система] Имя изменено на: {self.username}")
        
    def send_message_event(self, event):
        self.send_message()
        
    def send_message(self):
        message = self.message_entry.get().strip()
        if not message:
            return
            
        msg_type = self.message_type.get()
        
        if msg_type == "general":
            # Отправка в общий чат
            self.send_broadcast_message(message)
        elif msg_type == "private":
            # Отправка личного сообщения
            selection = self.users_listbox.curselection()
            if selection:
                recipient = self.users_listbox.get(selection[0])
                self.send_private_message(recipient, message)
            else:
                messagebox.showwarning("Выбор пользователя", 
                                      "Выберите пользователя для отправки ЛС")
                return
                
        self.message_entry.delete(0, tk.END)
        
    def send_broadcast_message(self, message):
        data = {
            'type': 'message',
            'username': self.username,
            'message': message,
            'timestamp': time.time(),
            'ip': self.local_ip
        }
        self.broadcast_data(data)
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.display_message(f"[{timestamp}] 💬 {self.username}: {message}")
        
    def send_private_message(self, recipient, message):
        if recipient in self.users:
            ip, port = self.users[recipient]
            data = {
                'type': 'private',
                'from': self.username,
                'message': message,
                'timestamp': time.time(),
                'ip': self.local_ip
            }
            try:
                self.message_socket.sendto(json.dumps(data).encode(), (ip, port))
                timestamp = datetime.now().strftime('%H:%M:%S')
                self.display_message(f"[{timestamp}] 🔒 → {recipient}: {message}")
            except Exception as e:
                self.display_message(f"[❌ Ошибка] Не удалось отправить сообщение: {str(e)}")
                
    def broadcast_presence(self):
        """Отправка широковещательного сообщения о присутствии"""
        data = {
            'type': 'presence',
            'username': self.username,
            'port': self.message_port,
            'timestamp': time.time(),
            'ip': self.local_ip
        }
        self.broadcast_data(data)
        
    def broadcast_data(self, data):
        """Отправка данных по широковещательному адресу"""
        try:
            data_str = json.dumps(data)
            
            # Отправляем на все возможные широковещательные адреса
            broadcast_ips = ['255.255.255.255']  # Основной широковещательный адрес
            
            # Пробуем вычислить широковещательный адрес для текущей подсети
            try:
                if self.local_ip != "127.0.0.1":
                    # Простая логика для получения broadcast адреса
                    ip_parts = self.local_ip.split('.')
                    if len(ip_parts) == 4:
                        broadcast_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
                        broadcast_ips.append(broadcast_ip)
            except:
                pass
            
            for broadcast_ip in broadcast_ips:
                try:
                    self.broadcast_socket.sendto(
                        data_str.encode(), 
                        (broadcast_ip, self.broadcast_port)
                    )
                except:
                    pass
                    
        except Exception as e:
            print(f"Ошибка при отправке: {e}")
                
    def listen_broadcasts(self):
        """Прослушивание широковещательных сообщений"""
        while self.running:
            try:
                data, addr = self.broadcast_socket.recvfrom(1024)
                message = json.loads(data.decode())
                
                if message['type'] == 'presence':
                    if message['username'] != self.username:
                        self.users[message['username']] = (addr[0], message['port'])
                        self.update_users_list()
                        # Обновляем статус
                        self.update_status(f"Пользователей онлайн: {len(self.users)}")
                        # Показываем в чате только при первом появлении
                        if message.get('timestamp', 0) > time.time() - 2:
                            self.display_message(f"[✅ Система] {message['username']} в сети")
                        
                elif message['type'] == 'message':
                    if message['username'] != self.username:
                        timestamp = datetime.fromtimestamp(message['timestamp']).strftime('%H:%M:%S')
                        display_msg = f"[{timestamp}] 💬 {message['username']}: {message['message']}"
                        self.display_message(display_msg)
                        
            except socket.timeout:
                continue
            except Exception as e:
                # Игнорируем ошибки декодирования
                if not isinstance(e, (json.JSONDecodeError, UnicodeDecodeError)):
                    pass
                
    def listen_messages(self):
        """Прослушивание личных сообщений"""
        while self.running:
            try:
                data, addr = self.message_socket.recvfrom(1024)
                message = json.loads(data.decode())
                
                if message['type'] == 'private':
                    timestamp = datetime.fromtimestamp(message['timestamp']).strftime('%H:%M:%S')
                    display_msg = f"[{timestamp}] 🔒 ← {message['from']}: {message['message']}"
                    self.display_message(display_msg)
                    
            except socket.timeout:
                continue
            except:
                pass
                
    def update_users_list(self):
        """Обновление списка пользователей в GUI"""
        self.root.after(0, self._update_users_list_gui)
        
    def _update_users_list_gui(self):
        self.users_listbox.delete(0, tk.END)
        for username in sorted(self.users.keys()):
            self.users_listbox.insert(tk.END, username)
            
    def update_status(self, text):
        """Обновление статуса"""
        self.root.after(0, lambda: self.status_label.config(text=text))
            
    def display_message(self, message):
        """Отображение сообщения в чате"""
        self.root.after(0, self._display_message_gui, message)
        
    def _display_message_gui(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + '\n')
        self.chat_area.config(state='disabled')
        self.chat_area.see(tk.END)
        
    def periodic_broadcast(self):
        """Периодическая отправка presence-сообщений"""
        while self.running:
            try:
                self.broadcast_presence()
                # Обновляем статус каждые 5 секунд
                if len(self.users) > 0:
                    self.update_status(f"Пользователей онлайн: {len(self.users)}")
                time.sleep(5)
            except:
                pass
            
    def cleanup(self):
        """Очистка ресурсов"""
        self.running = False
        if hasattr(self, 'broadcast_socket'):
            try:
                self.broadcast_socket.close()
            except:
                pass
        if hasattr(self, 'message_socket'):
            try:
                self.message_socket.close()
            except:
                pass
        
    def run(self):
        # Выбор IP при запуске
        selected_ip = self.choose_ip_dialog()
        self.setup_sockets(selected_ip)
        self.ip_label.config(text=f"IP: {self.local_ip}")
        self.status_label.config(text=f"Подключен с IP: {self.local_ip}")
        
        # Запускаем потоки
        broadcast_thread = threading.Thread(target=self.listen_broadcasts, daemon=True)
        message_thread = threading.Thread(target=self.listen_messages, daemon=True)
        presence_thread = threading.Thread(target=self.periodic_broadcast, daemon=True)
        
        broadcast_thread.start()
        message_thread.start()
        presence_thread.start()
        
        # Отправляем первое presence-сообщение
        self.broadcast_presence()
        self.display_message(f"[🚀 Система] Мессенджер запущен! Ваш IP: {self.local_ip}")
        self.display_message(f"[ℹ️ Система] Ваше имя: {self.username}")
        self.display_message(f"[ℹ️ Система] Для смены имени нажмите 'Сменить имя'")
        self.display_message(f"[ℹ️ Система] Для смены IP нажмите 'Сменить IP'")
        
        # Обработка закрытия окна
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Запускаем GUI
        self.root.mainloop()
        
    def on_closing(self):
        self.cleanup()
        self.root.destroy()

def main():
    app = P2PMessenger()
    app.run()

if __name__ == "__main__":
    main()