+++
title = "Hable con ventas"
description = "Trate con ApexMail los planes de despliegue empresarial, los requisitos de cumplimiento y las opciones de nube privada."
template = "prose.html"

[extra]
form_id = "sales-contact"
+++

## Hable con ventas

Para compras empresariales, revisiones de seguridad o planificación de nube privada, complete el formulario siguiente. Nuestro equipo revisa las solicitudes y responde en un plazo de 2 días laborables.

## Formulario de consulta de ventas

<div id="enquiry-submitted" class="form-banner form-banner--success" role="status" hidden>
  <p><strong>Gracias — su solicitud se ha recibido correctamente.</strong> Nuestro equipo la revisa y responde en un plazo de 2 días laborables.</p>
</div>
<div id="enquiry-error" class="form-banner form-banner--error" role="alert" hidden>
  <p><strong>No se ha podido aceptar su solicitud.</strong> Compruebe los campos obligatorios (se necesita un correo electrónico profesional válido) e inténtelo de nuevo.</p>
</div>
<form id="sales-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/sales">
  <input type="hidden" name="page_language" value="es" />
  <div>
    <label for="company" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Empresa <span class="text-red-500">*</span></label>
    <input type="text" id="company" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Nombre de su organización" />
  </div>

  <div>
    <label for="work-email" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Email profesional <span class="text-red-500">*</span></label>
    <input type="email" id="work-email" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="usted@empresa.com" />
  </div>

  <div class="grid sm:grid-cols-2 gap-6">
    <div>
      <label for="monthly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Volumen mensual de emails <span class="text-red-500">*</span></label>
      <select id="monthly-volume" name="monthly_volume" required
        class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
        <option value="" disabled selected>Seleccione un rango de volumen</option>
        <option value="lt_50k">Menos de 50.000</option>
        <option value="50k_150k">50.000 – 150.000</option>
        <option value="150k_500k">150.000 – 500.000</option>
        <option value="500k_2m">500.000 – 2 millones</option>
        <option value="2m_5m">2 millones – 5 millones</option>
        <option value="5m_10m">5 millones – 10 millones</option>
        <option value="10m_plus">Más de 10 millones</option>
      </select>
    </div>

    <div>
      <label for="peak-hourly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Volumen horario punta</label>
      <input type="text" id="peak-hourly-volume" name="peak_hourly_volume"
        class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
        placeholder="p. ej., 50.000 por hora" />
    </div>
  </div>

  <div>
    <label for="current-provider" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Proveedor actual</label>
    <select id="current-provider" name="current_provider"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Seleccione su proveedor actual (si tiene)</option>
      <option value="sendgrid">SendGrid (Twilio)</option>
      <option value="postmark">Postmark (ActiveCampaign)</option>
      <option value="mailgun">Mailgun (Sinch)</option>
      <option value="ses">Amazon SES</option>
      <option value="resend">Resend</option>
      <option value="mailchimp">Mailchimp / Mandrill</option>
      <option value="brevo">Brevo (Sendinblue)</option>
      <option value="other">Otro proveedor</option>
      <option value="none">Sin proveedor actual</option>
      <option value="multiple">Varios proveedores</option>
    </select>
  </div>

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Preferencia de despliegue</legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="shared" checked class="accent-brand-500" />
        <span><strong>Nube compartida</strong> — Infraestructura multi-tenant en la UE</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="dedicated" class="accent-brand-500" />
        <span><strong>Inquilino dedicado</strong> — Infraestructura aislada de inquilino único</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="byoc" class="accent-brand-500" />
        <span><strong>BYOC / Implementación privada</strong> — Despliegue gestionado en su propia cuenta cloud</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_preference" value="not_sure" class="accent-brand-500" />
        <span><strong>Aún no lo tengo claro</strong> — Necesito orientación sobre el modelo más adecuado</span>
      </label>
    </div>
  </fieldset>

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Requisitos de cumplimiento <span class="text-xs font-normal text-surface-400 normal-case tracking-normal">(seleccione todos los que apliquen)</span></legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="gdpr" class="accent-brand-500" />
        <span>RGPD / revisión de despliegue con residencia de datos</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="hipaa" class="accent-brand-500" />
        <span>Caso de uso HIPAA (no disponible actualmente; consultar alternativas)</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="soc2" class="accent-brand-500" />
        <span>Evidencias SOC 2 / ISO 27001</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="ccpa" class="accent-brand-500" />
        <span>CCPA / leyes de privacidad estatales de EE. UU.</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="fedramp" class="accent-brand-500" />
        <span>FedRAMP / sector público</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="regional_residency" class="accent-brand-500" />
        <span>Requisito específico de residencia regional de datos</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="checkbox" name="compliance_needs" value="dpf" class="accent-brand-500" />
        <span>Marco de Privacidad de Datos UE-EE. UU.</span>
      </label>
    </div>
  </fieldset>

  <div>
    <label for="target-timeline" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Plazo previsto</label>
    <select id="target-timeline" name="target_timeline"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Seleccione un plazo</option>
      <option value="immediate">Inmediato (en 2 semanas)</option>
      <option value="30_days">En 30 días</option>
      <option value="90_days">En 90 días</option>
      <option value="6_months">En 6 meses</option>
      <option value="exploring">Explorando opciones — sin plazo fijo</option>
    </select>
  </div>

  <div>
    <label for="security-review" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Necesidades de revisión de seguridad</label>
    <select id="security-review" name="security_review_needs"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" selected>Seleccione el nivel de revisión</option>
      <option value="standard">Estándar — cuestionario de seguridad respondido caso por caso con material de revisión actual (ningún paquete SIG/CAIQ/HECVAT estandarizado forma parte del producto)</option>
      <option value="detailed">Detallada — Se requiere un cuestionario de seguridad personalizado</option>
      <option value="pen_test">Se requiere informe de test de intrusión</option>
      <option value="on_site">Se requiere auditoría presencial o revisión de arquitectura</option>
      <option value="none">No se requiere revisión de seguridad en esta fase</option>
    </select>
  </div>

  <div>
    <label for="additional-context" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Contexto adicional</label>
    <textarea id="additional-context" name="additional_context" rows="4"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Requisitos específicos de integración, planes de migración, necesidades de arquitectura de seguridad o cualquier otro contexto que nos ayude a preparar la recomendación adecuada."></textarea>
  </div>

  <div>
    <button type="submit"
      class="btn-primary px-8 py-4 text-base uppercase w-full sm:w-auto">
      Enviar consulta
      <svg class="w-4 h-4 ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
    </button>
  </div>
  <p class="form-privacy-note">Al enviar este formulario, acepta nuestra <a href="/es/privacy/">política de privacidad</a>. Utilizamos estos datos únicamente para responder a su consulta (RGPD art. 13).</p>
</form>

## Qué sucede a continuación

Tras el envío, nuestro equipo empresarial revisa sus requisitos y responde en un plazo de 2 días laborables con un modelo de despliegue recomendado, precios orientativos y los siguientes pasos para una revisión de arquitectura estructurada.

Para contrataciones urgentes, envíe un email a [support@apexmail.ee](mailto:support@apexmail.ee) con el asunto "Urgent: Sales Enquiry" e incluya su volumen mensual y su preferencia de despliegue.
