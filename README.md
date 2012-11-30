dmiyakawa's misc SAML programs

meta_to_ssp_flat.py
This converts SAML's metadata xml to SimpleSAMLphp's flat-file format
(or, php config).

Remember this is not a "hands-free" implementation.
Although some fields are already implemented, not all of
metadata formats are accepted. Tested merely by SimpleSAMLphp's
metadata xml and one kind of Shibboleth IdP metadata.
The behavior is manually verified with OpenAM metadata, but
don't trust it much. You probably want to modify the emitted
flat-file or the program itself.
