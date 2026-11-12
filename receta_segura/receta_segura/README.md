Como iniciar programa:
dependencias: pip install -r requirements.txt

Como funciona:
se pueda crear una cuenta en registrar medico
Inicia sesión, llenar los datos de un paciente y hacer clic en "Generar receta PDF" para descargar el documento.
Ir a la pestaña Verificar receta  y sube el PDF que acabas de descargar. El sistema confirmará que la receta es válida.

Cifrado simétrico (Protección de datos sensibles)
Usamos el algoritmo AES-256-GCM. Protege el expediente clínico cifrando todos los datos sensibles (diagnóstico, nombre del paciente, medicamentos) antes de guardarlos en la base de datos. Si alguien extrae la base de datos, solo verá texto incomprensible.

Cifrado asimétrico (Verificación de integridad)
Usamos Ed25519, un algoritmo de curva elíptica. Al generar la receta, el sistema calcula el hash SHA-256 del contenido y del archivo PDF, y los firma digitalmente con la llave privada del médico. En el verificador, usamos la llave pública para comprobar matemáticamente que el PDF presentado es exactamente el mismo que salió del consultorio.

Gestión de llaves (Cero código hardcodeado)
Ninguna llave está escrita en el código fuente:
La llave maestra AES se guarda en un archivo oculto .env dentro de la carpeta local.
La llave privada del médico se guarda en la base de datos, pero está cifrada con su propia contraseña de inicio de sesión mediante el estándar PKCS8. Solo existe descifrada de forma temporal en la memoria RAM mientras la sesión está abierta.
La llave pública vive en la base de datos para que cualquiera pueda verificar las firmas.