import tkinter as tk
from tkinter import ttk

class BrutalistTheme:
    
    COLORS = {
        'background': '#FFFFFF',
        'foreground': '#000000',
        'button_bg': '#FFFFFF',
        'button_fg': '#000000',
        'button_active_bg': '#CCCCCC',
        'terminal_bg': '#FFFFFF',
        'terminal_fg': '#000000',
        'border': '#000000',
        'success': '#000000',
        'warning': '#000000',
        'error': '#000000'
    }
    
    FONTS = {
        'default': ('Courier', 10, 'normal'),
        'button': ('Courier', 10, 'bold'),
        'terminal': ('Courier', 9, 'normal'),
        'title': ('Courier', 12, 'bold'),
        'status': ('Courier', 8, 'normal')
    }
    
    DIMENSIONS = {
        'button_width': 20,
        'button_height': 2,
        'border_width': 3,
        'padding': 10,
        'section_padding': 20
    }

    @staticmethod
    def configure_root(root):
        root.configure(bg=BrutalistTheme.COLORS['background'])
        root.option_add('*Font', BrutalistTheme.FONTS['default'])
    
    @staticmethod
    def create_button(parent, text, command=None, state='normal'):
        button = tk.Button(
            parent,
            text=text,
            command=command,
            font=BrutalistTheme.FONTS['button'],
            bg=BrutalistTheme.COLORS['button_bg'],
            fg=BrutalistTheme.COLORS['button_fg'],
            activebackground=BrutalistTheme.COLORS['button_active_bg'],
            relief='solid',
            bd=BrutalistTheme.DIMENSIONS['border_width'],
            width=BrutalistTheme.DIMENSIONS['button_width'],
            height=BrutalistTheme.DIMENSIONS['button_height'],
            state=state
        )
        return button
    
    @staticmethod
    def create_label(parent, text, font_type='default'):
        label = tk.Label(
            parent,
            text=text,
            font=BrutalistTheme.FONTS[font_type],
            bg=BrutalistTheme.COLORS['background'],
            fg=BrutalistTheme.COLORS['foreground']
        )
        return label
    
    @staticmethod
    def create_frame(parent, relief='solid', bd=None):
        if bd is None:
            bd = BrutalistTheme.DIMENSIONS['border_width']
        
        frame = tk.Frame(
            parent,
            bg=BrutalistTheme.COLORS['background'],
            relief=relief,
            bd=bd
        )
        return frame
    
    @staticmethod
    def create_text_widget(parent, height=10, width=80):
        text_widget = tk.Text(
            parent,
            font=BrutalistTheme.FONTS['terminal'],
            bg=BrutalistTheme.COLORS['terminal_bg'],
            fg=BrutalistTheme.COLORS['terminal_fg'],
            relief='solid',
            bd=BrutalistTheme.DIMENSIONS['border_width'],
            height=height,
            width=width,
            wrap=tk.WORD,
            state='disabled',
            highlightthickness=0
        )
        return text_widget
    
    @staticmethod
    def create_scrollbar(parent, text_widget):
        scrollbar = tk.Scrollbar(
            parent,
            bg=BrutalistTheme.COLORS['background'],
            troughcolor=BrutalistTheme.COLORS['background'],
            activebackground=BrutalistTheme.COLORS['button_active_bg'],
            relief='solid',
            bd=BrutalistTheme.DIMENSIONS['border_width']
        )
        scrollbar.config(command=text_widget.yview)
        text_widget.config(yscrollcommand=scrollbar.set)
        return scrollbar