+++
title = "Contacto Enterprise"
description = "Solicite una revisión de despliegue Enterprise, una conversación sobre precios o una evaluación de nube privada con el equipo de ApexMail."
template = "prose.html"

[extra]
form_id = "enterprise-contact"
+++

## Contacto Enterprise

Para organizaciones que evalúan despliegues ApexMail Enterprise Shared, Dedicated Tenant o BYOC, utilice este formulario o escriba directamente a [support@apexmail.ee](mailto:support@apexmail.ee).

## Qué puede esperar

Tras enviar el formulario, nuestro equipo empresarial revisa sus requisitos y responde en un plazo de 2 días laborables con un modelo de despliegue recomendado, precios orientativos y los siguientes pasos para una revisión de arquitectura estructurada.

## Formulario de consulta Enterprise

<form id="enterprise-contact-form" class="space-y-6 max-w-2xl" method="POST" action="https://api.apexmail.ee/v1/contact/enterprise">
  <div>
    <label for="work-email" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Email profesional <span class="text-red-500">*</span></label>
    <input type="email" id="work-email" name="work_email" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="usted@empresa.com" />
  </div>

  <div>
    <label for="company" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Empresa <span class="text-red-500">*</span></label>
    <input type="text" id="company" name="company" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none"
      placeholder="Nombre de su organización" />
  </div>

  <div>
    <label for="monthly-volume" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Volumen mensual aproximado de emails <span class="text-red-500">*</span></label>
    <select id="monthly-volume" name="monthly_volume" required
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none">
      <option value="" disabled selected>Seleccione un rango de volumen</option>
      <option value="lt_100k">Menos de 100.000</option>
      <option value="100k_500k">100.000 – 500.000</option>
      <option value="500k_1m">500.000 – 1 millón</option>
      <option value="1m_5m">1 millón – 5 millones</option>
      <option value="5m_10m">5 millones – 10 millones</option>
      <option value="10m_50m">10 millones – 50 millones</option>
      <option value="50m_plus">Más de 50 millones</option>
    </select>
  </div>

  <fieldset class="border border-surface-200 p-4">
    <legend class="text-xs font-bold tracking-widest text-surface-600 uppercase px-2">Modelo de despliegue</legend>
    <div class="space-y-3 mt-3">
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="shared" checked class="accent-brand-500" />
        <span><strong>Nube compartida</strong> — Infraestructura multi-tenant en la UE</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="dedicated" class="accent-brand-500" />
        <span><strong>Inquilino dedicado</strong> — Infraestructura aislada de inquilino único, sujeta a revisión de arquitectura y contractual</span>
      </label>
      <label class="flex items-center gap-3 text-sm text-surface-700">
        <input type="radio" name="deployment_model" value="byoc" class="accent-brand-500" />
        <span><strong>BYOC / Implementación privada</strong> — Despliegue gestionado en su propia cuenta cloud, sujeto a revisión de arquitectura y contractual</span>
      </label>
    </div>
  </fieldset>

  <div>
    <label for="requirements" class="block text-xs font-bold tracking-widest text-surface-600 uppercase mb-2">Requisitos y contexto</label>
    <textarea id="requirements" name="requirements" rows="5"
      class="w-full px-4 py-3 border border-surface-300 text-sm text-surface-950 bg-surface-50 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 outline-none resize-y"
      placeholder="Requisitos de cumplimiento, necesidades de residencia de datos, proveedor actual, calendario de migración, funcionalidades específicas necesarias o cualquier otro contexto que nos ayude a preparar la recomendación adecuada."></textarea>
  </div>

  <div>
    <button type="submit"
      class="btn-primary px-8 py-4 text-base uppercase w-full sm:w-auto">
      Enviar consulta
      <svg class="w-4 h-4 ml-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
    </button>
  </div>
</form>

## Contacto directo

¿Prefiere el email? Contacte con el equipo empresarial en [support@apexmail.ee](mailto:support@apexmail.ee). Incluya su volumen mensual, su preferencia de modelo de despliegue y cualquier requisito de cumplimiento para que podamos prepararnos antes de la primera llamada.
