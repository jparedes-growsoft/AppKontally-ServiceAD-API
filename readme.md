# AppKontally-ServiceAD-API

Servicio **Windows / API REST** que centraliza la integración con **Active Directory** y **Kontally ERP**.  
Aplica políticas de **tenants, roles y pagos/suspensiones** y expone un **contrato HTTP seguro** consumido por la pasarela **ISAPI**.

---

## 🔎 Resumen

- **Fachada única a AD/ERP** (la ISAPI no toca AD ni BD directamente).
- **Reglas de negocio**: estado de tenant, verificación de acceso, suspensión/reactivación.
- **Seguridad**: TLS, API Keys/JWT, principio de mínimo privilegio.
- **Observabilidad**: health checks, logging y métricas básicas.
- **Versionado SemVer** y tabla de compatibilidad con la ISAPI.

---

## 🧭 Contenidos

- [Arquitectura](#arquitectura)
- [Tecnologías](#tecnologías)
- [Estructura del repositorio](#estructura-del-repositorio)
- [Configuración](#configuración)
- [Compilación y ejecución](#compilación-y-ejecución)
- [Endpoints (v1)](#endpoints-v1)
- [Seguridad](#seguridad)
- [Observabilidad](#observabilidad)
- [Versionado y compatibilidad](#versionado-y-compatibilidad)
- [Contribución](#contribución)
- [Licencia](#licencia)
- [Contacto](#contacto)

---

## Arquitectura
