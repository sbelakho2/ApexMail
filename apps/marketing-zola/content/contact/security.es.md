+++
title = "Solicitud de cuestionario de seguridad"
description = "Solicite documentación de seguridad de ApexMail, respuestas SIG/CAIQ, resúmenes de test de intrusión o programe una revisión de arquitectura de seguridad."
template = "prose.html"

[extra]
form_id = "security-contact"
+++

## Solicitud de cuestionario de seguridad

ApexMail proporciona documentación de seguridad a clientes y candidatos Enterprise cualificados, bajo NDA cuando sea necesario. Utilice este formulario para solicitar cuestionarios SIG, CAIQ, HECVAT o personalizados, o para programar una revisión de arquitectura de seguridad.

## Qué proporcionamos

- **SIG / CAIQ / HECVAT**, Respuestas estandarizadas de evaluación de seguridad para clientes Enterprise cualificados.
- **Resumen del test de intrusión**, Un resumen de hallazgos y correcciones estará disponible una vez completado el primer test de intrusión externo de la aplicación.
- **Revisión de arquitectura de seguridad**, Un recorrido por los controles de seguridad de ApexMail, su arquitectura de cifrado, el registro de auditoría y los modelos de aislamiento de despliegue.
- **Diagramas de flujo de datos**, Documentación visual del procesamiento de datos, las ubicaciones de almacenamiento y las relaciones con subprocesadores.

## Formulario de solicitud de cuestionario de seguridad

<div id="enquiry-submitted" class="apex-notice apex-notice--ok" role="status">
  <b>Recibida</b>
  <p>Gracias, su solicitud se ha recibido correctamente. Nuestro equipo la revisa y responde en un plazo de 2 días laborables.</p>
</div>
<div id="enquiry-error" class="apex-notice apex-notice--fail" role="alert">
  <b>No aceptada</b>
  <p>No se ha podido aceptar su solicitud. Compruebe los campos obligatorios (se necesita un correo electrónico profesional válido) e inténtelo de nuevo.</p>
</div>
<form id="security-questionnaire-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/security">
  <input type="hidden" name="page_language" value="es" />
  <div class="apex-field">
    <label for="work-email-sec" class="apex-label">Email profesional <span class="">*</span></label>
    <input type="email" id="work-email-sec" name="work_email" required autocomplete="email"
      class="apex-input"
      placeholder="usted@empresa.com" />
  </div>

  <div class="apex-field">
    <label for="company-sec" class="apex-label">Empresa <span class="">*</span></label>
    <input type="text" id="company-sec" name="company" required
      class="apex-input"
      placeholder="Nombre de su organización" />
  </div>

  <div class="apex-field">
    <label for="document-type" class="apex-label">Documentación solicitada <span class="">*</span></label>
    <div class="apex-select-wrap">
      <select id="document-type" name="document_type" required>
      <option value="" disabled selected>Seleccione lo que necesita</option>
      <option value="sig">Cuestionario SIG</option>
      <option value="caiq">Cuestionario CAIQ</option>
      <option value="hecvat">Cuestionario HECVAT</option>
      <option value="custom">Cuestionario de seguridad personalizado</option>
      <option value="pentest">Resumen del test de intrusión</option>
      <option value="architecture_review">Revisión de arquitectura de seguridad</option>
      <option value="data_flow">Diagramas de flujo de datos</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="nda-status" class="apex-label">Estado de la NDA</label>
    <div class="apex-select-wrap">
      <select id="nda-status" name="nda_status">
      <option value="not_signed" selected>NDA aún no firmada</option>
      <option value="signed">NDA ya en vigor</option>
      <option value="willing">Disponible para firmar la NDA</option>
    </select>
    </div>
  </div>

  <div class="apex-field">
    <label for="context" class="apex-label">Contexto adicional</label>
    <textarea id="context" name="context" rows="4"
      placeholder="Cualquier marco de cumplimiento específico, requisito regulatorio o restricción de plazos que debamos conocer."></textarea>
  </div>

  <div>
    <button type="submit"
      class="apex-btn apex-btn--primary w-full sm:w-auto">
      Enviar solicitud
    </button>
  </div>
  <p class="apex-footnote">Al enviar este formulario, acepta nuestra <a href="/es/privacy/">política de privacidad</a>. Utilizamos estos datos únicamente para responder a su consulta (RGPD art. 13).</p>
</form>

## Contacto directo

También puede enviar su solicitud de documentación de seguridad por correo electrónico a [support@apexmail.ee](mailto:support@apexmail.ee). Incluya el nombre de su empresa, los documentos o cuestionarios concretos que necesita y si ya existe una NDA en vigor o es necesaria.
