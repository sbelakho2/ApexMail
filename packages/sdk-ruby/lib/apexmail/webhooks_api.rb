# frozen_string: true

# The canonical implementation of {ApexMail::WebhooksAPI} lives in lib/apexmail.rb.
# This file previously carried a stale duplicate that would shadow the
# fixed methods when required after the main file; it now simply loads the
# canonical definition.
require_relative "../apexmail"
