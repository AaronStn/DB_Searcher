import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import difflib
import csv
import re

def fuerza_contraseña(pw):
    score = 0
    if len(pw) >= 8:
        score += 1
    if re.search(r'[A-Z]', pw):
        score += 1
    if re.search(r'[a-z]', pw):
        score += 1
    if re.search(r'\d', pw):
        score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', pw):
        score += 1
    fuerzas = {0: "Muy débil", 1: "Débil", 2: "Moderada", 3: "Buena", 4: "Fuerte", 5: "Muy fuerte"}
    return fuerzas.get(score, "Muy débil")

def guardar_datos(ruta, datos):
    try:
        with open(ruta, 'w', encoding='utf-8') as f:
            json.dump(datos, f, indent=2, ensure_ascii=False)
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo guardar el archivo:\n{e}")

class BuscadorUsuarios:

    def __init__(self, master):
        self.master = master
        master.title("Gestor Avanzado de Usuarios")
        master.geometry("920x680")
        master.configure(bg="#2e2e2e")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#fdf6e3", foreground="#073642", rowheight=25, fieldbackground="#eee8d5")
        style.map("Treeview", background=[("selected", "#b58900")])
        style.configure("TButton", font=("Segoe UI", 10), padding=5)
        style.configure("TLabel", background="#2e2e2e", foreground="#eee8d5", font=("Segoe UI", 11))
        style.configure("TEntry", padding=5)
        style.configure("TCombobox", padding=5)

        self.canvas = tk.Canvas(master, bg="#2e2e2e", highlightthickness=0)
        self.frame = tk.Frame(self.canvas, bg="#2e2e2e")
        self.vsb = ttk.Scrollbar(master, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.create_window((0,0), window=self.frame, anchor="nw")

        self.frame.bind("<Configure>", self.onFrameConfigure)

        self.datos = []
        self.ruta = None
        self.historial = []

        ttk.Button(self.frame, text="Cargar Base JSON", command=self.cargar_base).grid(row=0, column=0, padx=10, pady=10, sticky="w")

        ttk.Label(self.frame, text="Buscar por:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.opcion_buscar = ttk.Combobox(self.frame, values=["Usuario", "Correo", "IP"], state="readonly", width=15)
        self.opcion_buscar.current(0)
        self.opcion_buscar.grid(row=1, column=1, sticky="w")

        self.entrada_buscar = ttk.Entry(self.frame, width=30)
        self.entrada_buscar.grid(row=1, column=2, padx=10, pady=5)

        ttk.Button(self.frame, text="Buscar", command=self.buscar).grid(row=1, column=3, padx=10, pady=5)

        ttk.Button(self.frame, text="Exportar resultados CSV", command=self.exportar_csv).grid(row=1, column=4, padx=10, pady=5)

        ttk.Label(self.frame, text="Resultados Exactos").grid(row=2, column=0, columnspan=5, pady=(15,5))

        columnas = ('Usuario', 'Correo', 'Contraseña', 'IP')
        self.tabla_principal = ttk.Treeview(self.frame, columns=columnas, show='headings', height=6)
        for c in columnas:
            self.tabla_principal.heading(c, text=c)
            self.tabla_principal.column(c, width=200, anchor='center')
        self.tabla_principal.grid(row=3, column=0, columnspan=5, padx=10, sticky='nsew')
        self.tabla_principal.bind('<<TreeviewSelect>>', self.on_seleccionar)

        ttk.Label(self.frame, text="Resultados Similares").grid(row=4, column=0, columnspan=5, pady=(15,5))
        self.tabla_similares = ttk.Treeview(self.frame, columns=columnas, show='headings', height=8)
        for c in columnas:
            self.tabla_similares.heading(c, text=c)
            self.tabla_similares.column(c, width=200, anchor='center')
        self.tabla_similares.grid(row=5, column=0, columnspan=5, padx=10, sticky='nsew')
        self.tabla_similares.bind('<<TreeviewSelect>>', self.on_seleccionar)

        ttk.Label(self.frame, text="Editar o Agregar Usuario").grid(row=6, column=0, columnspan=5, pady=(20,5))

        ttk.Label(self.frame, text="Usuario:").grid(row=7, column=0, sticky='e', padx=5, pady=3)
        self.entry_usuario = ttk.Entry(self.frame, width=30)
        self.entry_usuario.grid(row=7, column=1, padx=5, pady=3)

        ttk.Label(self.frame, text="Correo:").grid(row=8, column=0, sticky='e', padx=5, pady=3)
        self.entry_correo = ttk.Entry(self.frame, width=30)
        self.entry_correo.grid(row=8, column=1, padx=5, pady=3)

        ttk.Label(self.frame, text="Contraseña:").grid(row=9, column=0, sticky='e', padx=5, pady=3)
        self.entry_pass = ttk.Entry(self.frame, width=30)
        self.entry_pass.grid(row=9, column=1, padx=5, pady=3)
        self.entry_pass.bind('<KeyRelease>', self.actualizar_fuerza_pass)

        self.label_fuerza = ttk.Label(self.frame, text="Fuerza contraseña: -")
        self.label_fuerza.grid(row=9, column=2, sticky='w')

        ttk.Label(self.frame, text="IP:").grid(row=10, column=0, sticky='e', padx=5, pady=3)
        self.entry_ip = ttk.Entry(self.frame, width=30)
        self.entry_ip.grid(row=10, column=1, padx=5, pady=3)

        ttk.Button(self.frame, text="Agregar Usuario", command=self.agregar_usuario).grid(row=11, column=0, pady=15)
        ttk.Button(self.frame, text="Modificar Usuario", command=self.modificar_usuario).grid(row=11, column=1, pady=15)

        ttk.Label(self.frame, text="Historial de búsquedas").grid(row=12, column=0, columnspan=5, pady=(10,5))
        self.lista_historial = tk.Listbox(self.frame, height=5, width=60)
        self.lista_historial.grid(row=13, column=0, columnspan=5, padx=10, sticky='ew')
        self.lista_historial.bind('<<ListboxSelect>>', self.cargar_historial)

        self.label_estadisticas = ttk.Label(self.frame, text="")
        self.label_estadisticas.grid(row=14, column=0, columnspan=5, pady=(15,15))

        for i in range(5):
            self.frame.grid_columnconfigure(i, weight=1)

    def onFrameConfigure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def cargar_base(self):
        ruta = filedialog.askopenfilename(title="Selecciona archivo JSON", filetypes=[("Archivos JSON", "*.json")])
        if ruta:
            try:
                with open(ruta, 'r', encoding='utf-8') as f:
                    self.datos = json.load(f)
                self.ruta = ruta
                self.historial.clear()
                self.actualizar_estadisticas()
                self.limpiar_tablas()
                messagebox.showinfo("Éxito", f"Base JSON cargada con {len(self.datos)} usuarios.")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer el archivo:\n{e}")

    def limpiar_tablas(self):
        for tabla in [self.tabla_principal, self.tabla_similares]:
            for fila in tabla.get_children():
                tabla.delete(fila)

    def buscar(self):
        self.limpiar_tablas()
        criterio_map = {
            "Usuario": "user",
            "Correo": "email",
            "IP": "ip_address"
        }
        criterio_seleccionado = self.opcion_buscar.get()
        clave = criterio_map.get(criterio_seleccionado, "user")

        texto = self.entrada_buscar.get().strip().lower()
        if not texto:
            messagebox.showwarning("Atención", "Ingrese texto para buscar.")
            return

        resultados_exactos = []
        resultados_similares = []

        for u in self.datos:
            campo = u.get(clave, '')
            if not isinstance(campo, str):
                campo = str(campo)
            campo_limpio = campo.strip().lower()

            if campo_limpio == texto:
                resultados_exactos.append(u)
            else:
                ratio = difflib.SequenceMatcher(None, campo_limpio, texto).ratio()
                if ratio >= 0.6:
                    resultados_similares.append((ratio, u))

        resultados_similares.sort(key=lambda x: x[0], reverse=True)
        resultados_similares = [x[1] for x in resultados_similares]

        for u in resultados_exactos:
            self.tabla_principal.insert('', 'end', values=(
                u.get('user', ''),
                u.get('email', ''),
                u.get('pass', ''),
                u.get('ip_address', '')
            ))

        for u in resultados_similares:
            self.tabla_similares.insert('', 'end', values=(
                u.get('user', ''),
                u.get('email', ''),
                u.get('pass', ''),
                u.get('ip_address', '')
            ))

        busqueda_texto = f"{self.opcion_buscar.get()}: {texto}"
        if busqueda_texto not in self.historial:
            self.historial.append(busqueda_texto)
            self.lista_historial.insert('end', busqueda_texto)

        self.actualizar_estadisticas()

    def actualizar_estadisticas(self):
        total = len(self.datos)
        fuertes = sum(1 for u in self.datos if fuerza_contraseña(u.get('pass', '')) in ['Fuerte', 'Muy fuerte'])
        debiles = sum(1 for u in self.datos if fuerza_contraseña(u.get('pass', '')) in ['Muy débil', 'Débil'])
        self.label_estadisticas.config(text=f"Total usuarios: {total} | Contraseñas fuertes: {fuertes} | Contraseñas débiles: {debiles}")

    def agregar_usuario(self):
        usuario = self.entry_usuario.get().strip()
        correo = self.entry_correo.get().strip()
        password = self.entry_pass.get().strip()
        ip = self.entry_ip.get().strip()

        if not usuario:
            messagebox.showwarning("Atención", "El usuario no puede estar vacío.")
            return
        if any(u.get('user', '') == usuario for u in self.datos):
            messagebox.showwarning("Atención", "El usuario ya existe.")
            return

        nuevo = {
            "user": usuario,
            "email": correo,
            "pass": password,
            "ip_address": ip
        }
        self.datos.append(nuevo)
        if self.ruta:
            guardar_datos(self.ruta, self.datos)
        messagebox.showinfo("Éxito", f"Usuario '{usuario}' agregado.")
        self.actualizar_estadisticas()
        self.limpiar_campos()

    def modificar_usuario(self):
        usuario = self.entry_usuario.get().strip()
        correo = self.entry_correo.get().strip()
        password = self.entry_pass.get().strip()
        ip = self.entry_ip.get().strip()

        if not usuario:
            messagebox.showwarning("Atención", "El usuario no puede estar vacío.")
            return

        encontrado = False
        for u in self.datos:
            if u.get('user', '') == usuario:
                u['email'] = correo
                u['pass'] = password
                u['ip_address'] = ip
                encontrado = True
                break

        if not encontrado:
            messagebox.showwarning("Atención", "Usuario no encontrado para modificar.")
            return

        if self.ruta:
            guardar_datos(self.ruta, self.datos)
        messagebox.showinfo("Éxito", f"Usuario '{usuario}' modificado.")
        self.actualizar_estadisticas()
        self.limpiar_campos()

    def actualizar_fuerza_pass(self, event=None):
        pw = self.entry_pass.get()
        fuerza = fuerza_contraseña(pw)
        self.label_fuerza.config(text=f"Fuerza contraseña: {fuerza}")

    def limpiar_campos(self):
        self.entry_usuario.delete(0, 'end')
        self.entry_correo.delete(0, 'end')
        self.entry_pass.delete(0, 'end')
        self.entry_ip.delete(0, 'end')
        self.label_fuerza.config(text="Fuerza contraseña: -")

    def on_seleccionar(self, event):
        tabla = event.widget
        seleccion = tabla.selection()
        if seleccion:
            valores = tabla.item(seleccion[0], 'values')
            if valores:
                self.entry_usuario.delete(0, 'end')
                self.entry_usuario.insert(0, valores[0])
                self.entry_correo.delete(0, 'end')
                self.entry_correo.insert(0, valores[1])
                self.entry_pass.delete(0, 'end')
                self.entry_pass.insert(0, valores[2])
                self.entry_ip.delete(0, 'end')
                self.entry_ip.insert(0, valores[3])
                self.actualizar_fuerza_pass()

    def exportar_csv(self):
        if not self.datos:
            messagebox.showwarning("Atención", "No hay datos para exportar.")
            return
        ruta = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if ruta:
            try:
                with open(ruta, 'w', newline='', encoding='utf-8') as f:
                    escritor = csv.writer(f)
                    escritor.writerow(['Usuario', 'Correo', 'Contraseña', 'IP'])
                    for u in self.datos:
                        escritor.writerow([
                            u.get('user', ''),
                            u.get('email', ''),
                            u.get('pass', ''),
                            u.get('ip_address', '')
                        ])
                messagebox.showinfo("Éxito", f"Datos exportados a {ruta}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo exportar el archivo:\n{e}")

    def cargar_historial(self, event):
        seleccion = self.lista_historial.curselection()
        if seleccion:
            texto = self.lista_historial.get(seleccion[0])
            if texto:
                parte = texto.split(': ', 1)
                if len(parte) == 2:
                    self.opcion_buscar.set(parte[0])
                    self.entrada_buscar.delete(0, 'end')
                    self.entrada_buscar.insert(0, parte[1])
                    self.buscar()

if __name__ == "__main__":
    root = tk.Tk()
    app = BuscadorUsuarios(root)
    root.mainloop()
