#!/usr/bin/python
#
# Converts SAML metadata xml to SimpleSAMLphp's flat file format.
#
# This supports both IdP and SP with limited support.
#
# TODO: rewrite this code based on correct model reflecting real
# SAML structure :-P

import sys
import xml.etree.ElementTree

class IndentedPrinter:

    def __init__(self, indent_size = 2):
        self.__indent_size = indent_size
        self.__indent_depth = 0
        self.__end_stack = []
        pass

    def print_line(self, str):
        indent = ' ' * (self.__indent_size * self.__indent_depth)
        print '%s%s' % (indent, str)
        pass

    def begin_block(self, start_str, end_str):
        indent = ' ' * (self.__indent_size * self.__indent_depth)
        print '%s%s' % (indent, start_str)
        self.__end_stack.append(end_str)
        self.__indent_depth += 1
        pass

    def end_block(self):
        assert(self.__indent_depth >= 1)
        self.__indent_depth -= 1
        indent = ' ' * (self.__indent_size * self.__indent_depth)
        print '%s%s' % (indent, self.__end_stack.pop())
        pass

    def end_all(self):
        assert(self.__indent_depth == 0)
        pass
    pass

'''
Prints the given error message using sys.stderr, and exit with sys.exit(1).
This never goes back to the caller side.
'''
def emit_error_and_exit(msg):
    print >>sys.stderr, msg
    sys.exit(1)
    pass

'''
For "RoleDescriptorType", see [SAMLMeta] 2.4.
This whole code just support SP/IDPSSODescriptor and
we want to ignore other kinds of descriptors.
Note that this code does NOT enumerate all of "other
descriptors".
Why? Because I was too lazy.
'''
def is_unsupported_role_descriptor_type(elem):
    return reduce((lambda x, y: x or y in elem.tag),
                  ['AttributeAuthorityDescriptor',
                   'PDPDescriptor',
                   'RoleDescriptor'], False)


def main(metadata_file):
    tree = xml.etree.ElementTree.parse(metadata_file)

    # TODO: group temporary variables here or construct
    # class for them. Then separate this huge method
    # into several logics.

    # Will be 'sp' or 'idp'
    idp_or_sp = None 
    entity_id = None

    # A hacky variable to remember if the current
    # element is in IDPSSODescriptor/SPSSODescriptor element
    # or not.
    #
    # If not, some fields must be ignored in the following logic,
    # which should not be in the resultant php config file for
    # SimpleSAMLphp.
    #
    # e.g.
    # KeyDescriptor for AttributeAuthorityDescriptor, which
    # appears on Shibboleth IdP (by default), should not be
    # remembered during this process. What we really need is
    # a certificate (and thus KeyDescriptor) for IDPSSODescriptor.
    #
    # <IDPSSODescriptor protocolSupportEnumeration="...">
    #   <KeyDescriptor>(cert A)</KeyDescriptor>
    # </IDPSSODescriptor>
    # <AttributeAuthorityDescriptor protocolSupportEnumeration="...">
    #   <KeyDescriptor>(cert B)</KeyDescriptor>
    # </AttributeAuthorityDescriptor>
    #
    # In the case above, only the cert A will be important for
    # SimpleSAMLphp.
    #
    # XXX: is this really really really true??
    in_sso_descriptor = False

    # Note: one metadata may contain two certs. See [SAMLMeta] 2.4.1.1.
    # This code will prioritize
    #  - first, value with "use='signing'",
    #  - second, value with no 'use' attribute, and
    #  - finally, value with "use='encryption'"
    x509_cert_map = {}
    x509_cur_key = None

    # sp
    assertion_consumer_service_list = []

    # idp
    name_id_format_list = []
    sso_service_list = []  # (Binding, Location)
    single_logout_service_list = []
    artifact_resolution_service_list = []

    # Iterate all elements and store some of them into temporary
    # variables. Because this code doesn't take care of xml's
    # correct tree structure, some ugly hacks are introduced.
    # (e.g. in_sso_descriptor)
    for elem in tree.iter():
        # debug
        # print elem.tag

        if 'EntitiesDescriptor' in elem.tag:
            emit_error_and_exit('Found EntitiesDescriptor. '
                                + 'It means this may '
                                + 'contain multiple metadata entries, '
                                + 'which is not supported. '
                                + 'Exiting..')
            pass
        elif 'AffiliationDescriptor' in elem.tag:
            emit_error_and_exit('AffiliationDescriptor is not supported. '
                                + 'Exiting..')
            pass
        elif 'EntityDescriptor' in elem.tag:
            if not elem.attrib.has_key('entityID'):
                emit_error_and_exit('EntityDescriptor does not have '
                                    + 'entityID attribute. Exiting..')
                pass
            entity_id = elem.attrib['entityID']
            pass
        elif ('IDPSSODescriptor' in elem.tag or
            'SPSSODescriptor' in elem.tag):
            if idp_or_sp:
                emit_error_and_exit('Multiple xxSSODescriptor'
                                    + 'Either IDPSSODescriptor or '
                                    + 'SPSSODescriptor. Exiting..')
                pass
            in_sso_descriptor = True
            if 'IDPSSODescriptor' in elem.tag:
                idp_or_sp = 'idp'
            else:
                idp_or_sp = 'sp'
                pass
            pass
        elif 'AssertionConsumerService' in elem.tag:  # sp
            binding = elem.attrib.get('Binding')
            location = elem.attrib.get('Location')
            index = elem.attrib.get('index', None)
            is_default = elem.attrib.get('isDefault', None)
            value = (binding, location, index, is_default)
            assertion_consumer_service_list.append(value)
            pass
        elif 'SingleSignOnService' in elem.tag:  # idp
            binding = elem.attrib.get('Binding')
            location = elem.attrib.get('Location')
            sso_service_list.append((binding, location))
            pass
        elif 'SingleLogoutService' in elem.tag:  # sp/idp
            binding = elem.attrib.get('Binding')
            location = elem.attrib.get('Location')
            response_location = elem.attrib.get('ResponseLocation')
            single_logout_service_list.append(
                (binding, location, response_location))
            pass
        elif 'ArtifactResolutionService' in elem.tag: # idp
            binding = elem.attrib.get('Binding')
            location = elem.attrib.get('Location')
            index = elem.attrib.get('index', None)
            is_default = elem.attrib.get('isDefault', None)
            value = (binding, location, index, is_default)
            artifact_resolution_service_list.append(value)
            pass
        elif is_unsupported_role_descriptor_type(elem):
            # Certs for RoleDescriptorType elements other than
            # IDPSSODescriptor/SPSSODescriptor are not needed.
            in_sso_descriptor = False
            pass
        elif in_sso_descriptor:
            if ('KeyDescriptor' in elem.tag) and in_sso_descriptor:
                if elem.attrib.has_key('use'):
                    key = elem.attrib['use']
                    pass
                else:
                    key = 'default'
                    pass
                if key not in ['default', 'signing', 'encryption']:
                    emit_error_and_exit('Unknown "use" attribute of '
                                        + 'KeyDescriptor: %s. Exiting..'
                                        % key)
                    pass
                if x509_cert_map.has_key(key):
                    emit_error_and_exit(('Mutliple KeyDescriptor entry '
                                         + 'for use="%s" attribute. '
                                         + 'Exiting..') % key)
                    pass
                x509_cur_key = key
                pass
            elif ('X509Certificate' in elem.tag) and in_sso_descriptor:
                if not x509_cur_key:
                    emit_error_and_exit('X509Certificate shows up while '
                                        + 'no KeyDescripter is detected. '
                                        + 'Exiting..')
                    pass
                cert = ''.join(elem.text.split())
                x509_cert_map[x509_cur_key] = cert
                x509_cur_key = None
                pass
            elif 'NameIDFormat' in elem.tag:  # idp
                name_id_format_list.append(elem.text.strip())
                pass
            pass

        pass # end of 'for elem'

    if idp_or_sp not in ['idp', 'sp']:
        emit_error_and_exit('Unknown provider: %s. Exiting..'
                            % idp_or_sp)
        pass

    # Start printing an actual flat-file format for SimpleSAMLphp.
    # TODO: define another function for the printing part..

    print 'metadata for ' + idp_or_sp
    print

    p = IndentedPrinter()
    p.begin_block("$metadata['%s'] = array (" % entity_id, ");")
    if idp_or_sp == 'idp':
        p.print_line("'name' => 'ssp_flat',")
        p.print_line("'metadata-set' => 'saml20-idp-remote',")
        p.print_line("'entityid' => '%s'," % entity_id)

        # SingleSignOnService
        if len(sso_service_list) > 0:
            p.begin_block("'SingleSignOnService' => array (", "),")
            for i, (binding, location) in enumerate(sso_service_list):
                p.print_line("%d =>" % i)
                p.begin_block("array (", "),")
                p.print_line("'Binding' => '%s'," % binding)
                p.print_line("'Location' => '%s'," % location)
                p.end_block()
                pass
            p.end_block()
            pass

        if len(artifact_resolution_service_list) > 0:
            p.begin_block("'ArtifactResolutionService' => array (", "),")
            for i, (binding, location, index, is_default) in \
                    enumerate(artifact_resolution_service_list):
                p.print_line("%d =>" % i)
                p.begin_block("array (", "),")
                p.print_line("'Binding' => '%s'," % binding)
                p.print_line("'Location' => '%s'," % location)
                if index:
                    p.print_line("'index' => %s," % index)
                    pass
                if is_default:
                    p.print_line("'isDefault' => '%s'," % is_default)
                    pass
                p.end_block()
                pass
            p.end_block()
        pass
    else: # sp

        # AssertionConsumerService
        acs_size = len(assertion_consumer_service_list)
        if acs_size == 0:
            emit_error_and_exit('No AssertionConsumerService in SP.'
                                + 'Exiting..')
            pass
        elif acs_size == 1:
            (binding, location, index, is_default) = \
                assertion_consumer_service_list[0]
            p.print_line("'AssertionConsumerService' => '%s'," % location)
        else:
            p.begin_block("'AssertionConsumerService' => array (", "),")
            for elem in assertion_consumer_service_list:
                (binding, location, index, is_default) = elem
                if '1.0' in binding:
                    continue
                p.begin_block("array (", "),")
                p.print_line("'Binding' => '%s'," % binding)
                p.print_line("'Location' => '%s'," % location)
                # if index:
                # p.print_line("'index' => %s," % index)
                # pass
                if is_default:
                    p.print_line("'isDefault' => '%s'," % is_default)
                    pass
                p.end_block()
                pass
            p.end_block()
        pass

    ## common elements among idp and sp

    # SingleLogoutService
    if len(single_logout_service_list) > 0:
        if len(single_logout_service_list) == 1:
            (binding, location, response_location) = \
                single_logout_service_list[0]
            p.print_line("'SingleLogoutService' => '%s'," %
                         location)
            pass
        else:
            p.begin_block("'SingleLogoutService' => array (", "),")
            for i, (binding, location, response_location) in \
                    enumerate(single_logout_service_list):
                p.begin_block("array (", "),")
                p.print_line("'Binding' => '%s'," % binding)
                p.print_line("'Location' => '%s'," % location)
                if response_location:
                    p.print_line("'ResponseLocation' => '%s'," %
                                 response_location)
                    pass
                p.end_block()
                pass
            p.end_block()
            pass
        pass

    # NameIdFormat: prefer transient, email, and persistent
    transient = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
    persistent = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
    email = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    email_ssp = 'urn:oasis:names:tc:SAML:2.0:nameid-format:email'
    if transient in name_id_format_list:
        p.print_line("'NameIDFormat' => '%s'," % transient)
        pass
    elif persistent in name_id_format_list:
        p.print_line("NameIDFormat' => '%s'," % persistent)
        pass
    elif email in name_id_format_list or email_ssp in name_id_format_list:
        p.print_line("'NameIDFormat' => '%s'," % email_ssp)
        pass

    # Certificate
    # TODO: figure out how 'signing' and 'encryption' are treated
    # technically and when they become different.
    x509_cert = None
    if x509_cert_map.has_key('signing'):
        x509_cert = x509_cert_map['signing']
        pass
    elif x509_cert_map.has_key('default'):
        x509_cert = x509_cert_map['default']
        pass
    elif x509_cert_map.has_key('encryption'):
        x509_cert = x509_cert_map['encryption']
        pass
    if x509_cert:
        print "  'certData' => '%s'," % x509_cert
        pass

    p.end_block()
    p.end_all()
    pass

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print >>sys.stderr, 'usage: %s metadata'
        sys.exit(1)
        pass
    main(sys.argv[1])
    pass
