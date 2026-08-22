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

- **SIG / CAIQ / HECVAT** — Respuestas estandarizadas de evaluación de seguridad para clientes Enterprise cualificados.
- **Resumen del test de intrusión** — Un resumen de hallazgos y correcciones estará disponible una vez completado el primer test de intrusión externo de la aplicación.
- **Mapeo de controles SOC 2** — Documentación del mapeo de controles según los criterios Trust Services Criteria de SOC 2 y de la evaluación de preparación (nota: ApexMail no cuenta actualmente con la certificación SOC 2).
- **Revisión de arquitectura de seguridad** — Un recorrido por los controles de seguridad de ApexMail, su arquitectura de cifrado, el registro de auditoría y los modelos de aislamiento de despliegue.
- **Diagramas de flujo de datos** — Documentación visual del procesamiento de datos, las ubicaciones de almacenamiento y las relaciones con subprocesadores.

## Formulario de solicitud de cuestionario de seguridad

<form id="security-questionnaire-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/security">
  <div>
    <label for="work-email-sec" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Email profesional <span class="text-red-500">*</span></label>
    <input type="email" id="work-email-sec" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="usted@empresa.com" />
  </div>

  <div>
    <label for="company-sec" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Empresa <span class="text-red-500">*</span></label>
    <input type="text" id="company-sec" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Nombre de su organización" />
  </div>

  <div>
    <label for="document-type" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Documentación solicitada <span class="text-red-500">*</span></label>
    <select id="document-type" name="document_type" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" disabled selected>Seleccione lo que necesita</option>
      <option value="sig">Cuestionario SIG</option>
      <option value="caiq">Cuestionario CAIQ</option>
      <option value="hecvat">Cuestionario HECVAT</option>
      <option value="custom">Cuestionario de seguridad personalizado</option>
      <option value="pentest">Resumen del test de intrusión</option>
      <option value="soc2">Mapeo de controles SOC 2</option>
      <option value="architecture_review">Revisión de arquitectura de seguridad</option>
      <option value="data_flow">Diagramas de flujo de datos</option>
    </select>
  </div>

  <div>
    <label for="nda-status" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Estado de la NDA</label>
    <select id="nda-status" name="nda_status"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="not_signed" selected>NDA aún no firmada</option>
      <option value="signed">NDA ya en vigor</option>
      <option value="willing">Disponible para firmar la NDA</option>
    </select>
  </div>

  <div>
    <label for="context" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Contexto adicional</label>
    <textarea id="context" name="context" rows="4"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Cualquier marco de cumplimiento específico, requisito regulatorio o restricción de plazos que debamos conocer."></textarea>
  </div>

  <div>
    <button type="submit"
      class="btn-primary px-8 py-4 text-base uppercase w-full sm:w-auto">
      Enviar solicitud
      <svg class="w-4 h-4 ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
    </button>
  </div>
</form>

## Contacto directo

¿Prefiere el email? Envíe su solicitud de documentación de seguridad a [support@apexmail.ee](mailto:support@apexmail.ee). Incluya el nombre de su empresa, los documentos o cuestionarios concretos que necesita y si ya existe una NDA en vigor o es necesaria.
