from core.config import get_settings

settings = get_settings()
print("From .env:", repr(settings.censys_pat))
print("Length:", len(settings.censys_pat) if settings.censys_pat else 0)

# Compare directly against the one that worked:
hardcoded = "<censys_spi_key>"  # replace the api with your actual censys api key
print("Match:", settings.censys_pat == hardcoded)