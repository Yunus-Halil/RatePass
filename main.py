import sys
import json
import re
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QLineEdit, QListWidget, QListWidgetItem, 
    QMessageBox, QDialog, QComboBox, QFrame, QColorDialog, 
    QProgressBar, QMenu
)
from PyQt6.QtCore import QPropertyAnimation, QRect, QEasingCurve, Qt
from PyQt6.QtGui import QColor, QIcon
from cryptography.fernet import Fernet
import os

# Generate a new key and save it to a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the previously generated key

def load_key():
    if not os.path.exists("secret.key"):
        generate_key()  # Generate a new key if it doesn't exist
    return open("secret.key", "rb").read()

def encrypt_password(password):
    key = load_key()
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password


def decrypt_password(encrypted_password):
    key = load_key()
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

# Preset themes for the drop-down
PRESET_THEMES = {
    "Modern Dark": {
        "background": "#2E2E2E",
        "secondary_background": "#3D3D3D",
        "card_background": "#454545",
        "accent": "#007AFF",
        "text": "#FFFFFF"
    },
    "Light Mode": {
        "background": "#F5F5F5",
        "secondary_background": "#FFFFFF",
        "card_background": "#FFFFFF",
        "accent": "#007AFF",
        "text": "#000000"
    },
    "Cafe": {
        "background": "#D9CBAE",
        "secondary_background": "#BFAF8D",
        "card_background": "#E6D8C5",
        "accent": "#7B5B3A",
        "text": "#3B2A1A"
    },
    "Ocean": {
        "background": "#A3D8E0",
        "secondary_background": "#E0F7FA",
        "card_background": "#B2EBF2",
        "accent": "#00796B",
        "text": "#004D40"
    },
    "Nature": {
        "background": "#D9EAD3",
        "secondary_background": "#C3D9B9",
        "card_background": "#E6F9D9",
        "accent": "#4CAF50",
        "text": "#2E7D32"
    },
    "Rain": {
        "background": "#B0BEC5",
        "secondary_background": "#CFD8DC",
        "card_background": "#ECEFF1",
        "accent": "#607D8B",
        "text": "#263238"
    },
    "Sunset": {
        "background": "#FFCCBC",
        "secondary_background": "#FFAB91",
        "card_background": "#FF8A65",
        "accent": "#D84315",
        "text": "#BF360C"
    }
}

class AnimatedButton(QPushButton):
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self._animation = QPropertyAnimation(self, b"geometry")
        self._animation.setDuration(100)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def set_theme(self, theme):
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {theme['accent']};
                color: {theme['text']};
                border: 2px solid transparent;  /* Default border */
                border-radius: 5px;
                padding: 8px 16px;
            }}
            QPushButton:hover {{
                background-color: {self.darker_color(theme['accent'])};
                border: 2px solid {theme['text']};  /* Outline on hover */
            }}
            QPushButton:pressed {{
                background-color: {self.darker_color(theme['accent'])};  /* Change color when pressed */
                border: 2px solid {theme['text']};  /* Keep the outline when pressed */
            }}
        """)

    def darker_color(self, color):
        """Return a darker shade of the given color."""
        color = QColor(color)
        return color.darker(150).name()  # Call the method and return the color in hex format

    def enterEvent(self, event ):
        geo = self.geometry()
        self._animation.setStartValue(geo)
        self._animation.setEndValue(QRect(geo.x(), geo.y() - 2, geo.width(), geo.height()))
        self._animation.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        geo = self.geometry()
        self._animation.setStartValue(geo)
        self._animation.setEndValue(QRect(geo.x(), geo.y() + 2, geo.width(), geo.height()))
        self._animation.start()
        super().leaveEvent(event)

class ThemeCustomizer(QDialog):
    def __init__(self, current_theme, parent=None):
        super().__init__(parent)
        self.current_theme = current_theme.copy()
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Customize Theme")
        layout = QVBoxLayout(self)

        # Preset themes dropdown
        preset_layout = QHBoxLayout()
        preset_label = QLabel("Preset Themes:")
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(PRESET_THEMES.keys())
        self.preset_combo.currentTextChanged.connect(self.load_preset)
        preset_layout.addWidget(preset_label)
        preset_layout.addWidget(self.preset_combo)
        layout.addLayout(preset_layout)

        # Color buttons
        self.color_buttons = {}
        for key in self.current_theme:
            btn_layout = QHBoxLayout()
            label = QLabel(key.replace("_", " ").title() + ":")
            btn = QPushButton()
            btn.setFixedSize(50, 25)
            btn.clicked.connect(lambda checked, k=key: self.choose_color(k))
            self.color_buttons[key] = btn
            btn_layout.addWidget(label)
            btn_layout.addWidget(btn)
            layout.addLayout(btn_layout)

        # OK/Cancel buttons
        buttons_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        ok_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)
        layout.addLayout(buttons_layout)

        self.update_color_buttons()

    def choose_color(self, key):
        color = QColorDialog.getColor(QColor(self.current_theme[key]), self)
        if color.isValid():
            self.current_theme[key] = color.name()
            self.update_color_buttons()

    def update_color_buttons(self):
        for key, button in self.color_buttons.items():
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {self.current_theme[key]};
                    border: none;
                    border-radius: 3px;
                }}
            """)

    def load_preset(self, preset_name):
        if preset_name in PRESET_THEMES:
            self.current_theme = PRESET_THEMES[preset_name].copy()
            self.update_color_buttons()

class PasswordStrengthMeter(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.load_common_passwords()

    def load_common_passwords(self):
        try:
            with open('common_passwords.txt', 'r') as f:
                self.common_passwords = set(line.strip().lower() for line in f)
        except FileNotFoundError:
            self.common_passwords = set()
            print("Warning: common_passwords.txt not found")

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Create strength meter
        self.strength_meter = QProgressBar()
        self.strength_meter.setMaximum(6)
        self.strength_meter.setMinimum(0)
        self.strength_meter.setTextVisible(False)
        
        # Create requirement labels
        self.requirements_frame = QFrame()
        req_layout = QVBoxLayout(self.requirements_frame)
        self.requirement_labels = {
            'length': QLabel('❌ At least 8 characters'),
            'uppercase': QLabel('❌ Contains uppercase letter'),
            'lowercase': QLabel('❌ Contains lowercase letter'),
            'number': QLabel('❌ Contains number'),
            'special': QLabel('❌ Contains special character'),
            'common': QLabel('❌ Not a common password')
        }
        
        for label in self.requirement_labels.values():
            req_layout.addWidget(label)

        # Create toggle button for requirements
        self.toggle_button = QPushButton()
        self.toggle_button.setIcon(QIcon('eye.png'))  # Set the icon
        self.toggle_button.setCheckable(True)  # Make it checkable
        self.toggle_button.clicked.connect(self.toggle_requirements)
        
        layout.addWidget(self.strength_meter)
        layout.addWidget(self.requirements_frame)
        layout.addWidget(self.toggle_button)  # Add toggle button to layout

    def toggle_requirements(self):
        # Toggle visibility of the requirements frame
        is_visible = self.requirements_frame.isVisible()
        self.requirements_frame.setVisible(not is_visible)

        # Change button icon based on visibility
        if is_visible:
            self.toggle_button.setIcon(QIcon('eye.png'))  # Show icon
        else:
            self.toggle_button.setIcon(QIcon('eye_off.png '))  # Hide icon (use a different icon for the 'off' state)

    def check_password_strength(self, password):
        requirements_met = 0
        
        # Check length
        if len(password) >= 8:
            self.requirement_labels['length'].setText('✅ At least 8 characters')
            requirements_met += 1
        else:
            self.requirement_labels['length'].setText('❌ At least 8 characters')
        
        # Check uppercase
        if re.search(r'[A-Z]', password):
            self.requirement_labels['uppercase'].setText('✅ Contains uppercase letter')
            requirements_met += 1
        else:
            self.requirement_labels['uppercase'].setText('❌ Contains uppercase letter')
        
        # Check lowercase
        if re.search(r'[a-z]', password):
            self.requirement_labels['lowercase'].setText('✅ Contains lowercase letter')
            requirements_met += 1
        else:
            self.requirement_labels['lowercase'].setText('❌ Contains lowercase letter')
        
        # Check numbers
        if re.search(r'\d', password):
            self.requirement_labels['number'].setText('✅ Contains number')
            requirements_met += 1
        else:
            self.requirement_labels['number'].setText('❌ Contains number')
        
        # Check special characters
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password ):
            self.requirement_labels['special'].setText('✅ Contains special character')
            requirements_met += 1
        else:
            self.requirement_labels['special'].setText('❌ Contains special character')
        
        # Check if password is common
        if password.lower() not in self.common_passwords:
            self.requirement_labels['common'].setText('✅ Not a common password')
            requirements_met += 1
        else:
            self.requirement_labels['common'].setText('❌ Not a common password')
        
        self.strength_meter.setValue(requirements_met)
        return requirements_met

    def set_theme(self, theme):
        # Style the progress bar
        self.strength_meter.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                border-radius: 3px;
                background-color: {theme['secondary_background']};
                height: 10px;
            }}
            QProgressBar ::chunk {{
                background-color: {theme['accent']};
                border-radius: 3px;
            }}
        """)
        
        # Style the requirement labels
        for label in self.requirement_labels.values():
            label.setStyleSheet(f" color: {theme['text']};")

class ModernPasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.passwords = {}
        self.current_theme = PRESET_THEMES["Modern Dark"].copy()
        self.load_passwords()
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        self.setWindowTitle("RatePass V.1.0")
        self.setMinimumSize(600, 500)

        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Create header
        header = QFrame()
        header_layout = QHBoxLayout(header)
        title = QLabel("RatePass")
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        theme_button = AnimatedButton("Customize Theme")
        theme_button.clicked.connect(self.customize_theme)
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(theme_button)

        # Create input section
        input_frame = QFrame()
        input_layout = QVBoxLayout(input_frame)  # Changed to VBoxLayout
        
        # Create horizontal layout for service and username
        credentials_layout = QHBoxLayout()
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText("Service")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        credentials_layout.addWidget(self.service_input)
        credentials_layout.addWidget(self.username_input)
        
        # Create password section
        password_section = QVBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_strength_meter = PasswordStrengthMeter()
        self.password_input.textChanged.connect(
            lambda text: self.password_strength_meter.check_password_strength(text)
        )
        
        password_section.addWidget(self.password_input)
        password_section.addWidget(self.password_strength_meter)
        
        # Add button
        add_button = AnimatedButton("Add Password")
        add_button.clicked.connect(self.add_password)
        
        # Add all sections to input layout
        input_layout.addLayout(credentials_layout)
        input_layout.addLayout(password_section)
        input_layout.addWidget(add_button)

        # Create password list
        self.password_list = QListWidget()
        self.password_list.itemDoubleClicked.connect(self.show_password)
        self.password_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.password_list.customContextMenuRequested.connect(self.show_context_menu)

        # Add all components to main layout
        main_layout.addWidget(header)
        main_layout.addWidget(input_frame)
        main_layout.addWidget(self.password_list)

        # Update password list
        self.update_password_list()

    def apply_theme(self):
        # Apply theme to main window
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {self.current_theme['background']};
                
            }}
            QLabel {{
                color: {self.current_theme['text']};
            }}
            QLineEdit {{
                background-color: {self.current_theme['secondary_background']};
                color: {self.current_theme['text']};
                border: none;
                border-radius: 5px;
                padding: 8px;
            }}
            QListWidget {{
                background-color: {self.current_theme['secondary_background']};
                color: {self.current_theme['text']};
                border: none;
                border-radius: 5px;
            }}
            QListWidget::item {{
                background-color: {self.current_theme['card_background']};
                margin: 5px;
                padding: 10px;
                border-radius: 5px;
            }}
        """)

        # Update theme for all AnimatedButtons and PasswordStrengthMeter
        for button in self.findChildren(AnimatedButton):
            button.set_theme(self.current_theme)
        self.password_strength_meter.set_theme(self.current_theme)

    def add_password (self):
        service = self.service_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        

        if service and username and password:
            strength = self.password_strength_meter.check_password_strength(password)
            if strength < 4:
                response = QMessageBox.question(
                    self,
                    "Weak Password",
                    "This password is weak. Are you sure you want to save it?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if response == QMessageBox.StandardButton.No:
                    return

            encrypted_password = encrypt_password(password)
            self.passwords[service] = {
                'username': username,
                'password': encrypted_password.decode()  # Store the encrypted password as a string
            }
            self.save_passwords()
            self.update_password_list()
            self.clear_inputs()
        else:
            QMessageBox.warning(self, "Input Error", "Please fill in all fields.")

    def clear_inputs(self):
        self.service_input.clear()
        self.username_input.clear()
        self.password_input.clear()

    def update_password_list(self):
        self.password_list.clear()
        for service in sorted(self.passwords.keys()):
            username = self.passwords[service].get('username', 'Unknown User')  # Default to 'Unknown User' if key is missing
            item = QListWidgetItem(f"{service} - {username}")
            self.password_list.addItem(item)

    def show_password(self, item):
        service = item.text().split(" - ")[0]
        if service in self.passwords:
            encrypted_password = self.passwords[service].get('password', 'Unknown Password')
            decrypted_password = decrypt_password(encrypted_password.encode())
            username = self.passwords[service].get('username', 'Unknown User')
            QMessageBox.information(
                self,
                "Password Details",
                f"Service: {service}\nUsername: {username}\nPassword: {decrypted_password}"
            )

    def customize_theme(self):
        dialog = ThemeCustomizer(self.current_theme, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.current_theme = dialog.current_theme
            self.apply_theme()

    def save_passwords(self):
        try:
            with open('passwords.json', 'w') as f:
                json.dump(self.passwords, f)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save passwords: {str(e)}")

    def load_passwords(self):
        try:
            with open('passwords.json', 'r') as f:
                self.passwords = json.load(f)
                # Validate the structure of the loaded passwords
                for service in list(self.passwords.keys()):
                    if 'username' not in self.passwords[service] or 'password' not in self.passwords[service]:
                        print(f"Warning: Missing keys in service '{service}'. Removing it .")
                        del self.passwords[service]  # Remove invalid entry
        except FileNotFoundError:
            self.passwords = {}
        except json.JSONDecodeError :
            QMessageBox.warning(self, "Error", "Failed to decode passwords JSON. The file may be corrupted.")
            self.passwords = {}
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load passwords: {str(e)}")
            self.passwords = {}

    def show_context_menu(self, position):
        item = self.password_list.itemAt(position)
        if item is None:
            return

        service = item.text().split(" - ")[0]
        menu = QMenu(self)

        edit_action = menu.addAction(QIcon('edit.png'), "Edit")
        delete_action = menu.addAction(QIcon('trash.png'), "Delete")

        action = menu.exec(self.password_list.viewport().mapToGlobal(position))

        if action == edit_action:
            self.edit_password(service)
        elif action == delete_action:
            self.delete_password(service)

    def edit_password(self, service):
        if service in self.passwords:
            encrypted_password = self.passwords[service].get('password', 'Unknown Password')
            decrypted_password = decrypt_password(encrypted_password.encode())
            dialog = PasswordEditDialog(service, self.passwords[service].get('username', 'Unknown User'), decrypted_password, self)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                new_values = dialog.get_values()
                encrypted_password = encrypt_password(new_values['password'])
                self.passwords[service] = {
                    'username': new_values['username'],
                    'password': encrypted_password.decode()
                }
                self.save_passwords()
                self.update_password_list()

    def delete_password(self, service):
        if service in self.passwords:
            response = QMessageBox.question(
                self,
                "Delete Password",
                f"Are you sure you want to delete the password for {service}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if response == QMessageBox.StandardButton.Yes:
                del self.passwords[ service]
                self.save_passwords()
                self.update_password_list()

class PasswordEditDialog(QDialog):
    def __init__(self, service, username, password, parent=None):
        super().__init__(parent)
        self.service = service
        self.username = username
        self.password = password
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Edit Password")
        layout = QVBoxLayout(self)

        # Service
        service_layout = QHBoxLayout()
        service_label = QLabel("Service:")
        self.service_input = QLineEdit(self.service)
        self.service_input.setReadOnly(True)
        service_layout.addWidget(service_label)
        service_layout.addWidget(self.service_input)
        layout.addLayout(service_layout)

        # Username
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        self.username_input = QLineEdit(self.username)
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        layout.addLayout(username_layout)

        # Password
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        self.password_input = QLineEdit(self.password)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)

        # OK/Cancel buttons
        buttons_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        ok_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)
        layout.addLayout(buttons_layout)

    def get_values(self):
        return {
            'username': self.username_input.text(),
            'password': self.password_input.text()
        }

def main():
    app = QApplication(sys.argv)
    window = ModernPasswordManager()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
