from django.contrib import admin
from api.models import Site, SiteAccount

class SiteAccountAdminInline(admin.TabularInline):
    model = SiteAccount
    extra = 0
    readonly_fields = ('hotp_iteration', 'hotp_key')

class SiteAdmin(admin.ModelAdmin):
    inlines = (SiteAccountAdminInline, )

admin.site.register(Site, SiteAdmin)