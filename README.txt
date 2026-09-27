REY SAVINO CRM - PROYECTO PARA VERCEL

Incluye login del lado servidor con cookie HttpOnly firmada, CRM protegido y cierre de sesión.
La base comercial actual continúa almacenándose en localStorage del navegador. Por ello, los datos no se sincronizan automáticamente entre computadoras o celulares.

Archivos principales:
- index.html: pantalla de acceso
- crm.html: CRM
- api/login.js: autenticación
- api/session.js: validación de sesión
- api/logout.js: cierre de sesión
- api/app.js: entrega el CRM solo si la sesión es válida
- vercel.json: configuración de despliegue
