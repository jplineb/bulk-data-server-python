import config from "../../config";

export default {
    "resourceType": "OperationDefinition",
    "id": "group-export",
    "text": {
        "status": "generated",
        "div": "<div xmlns=\"http://www.w3.org/1999/xhtml\"><p class=\"res-header-id\"><b>Generated Narrative: OperationDefinition group-export</b></p><a name=\"group-export\"> </a><a name=\"hcgroup-export\"> </a><a name=\"group-export-en-US\"> </a><p>URL: [base]/Group/[id]/$export</p><h3>Parameters</h3><table class=\"grid\"><tr><td><b>Use</b></td><td><b>Name</b></td><td><b>Scope</b></td><td><b>Cardinality</b></td><td><b>Type</b></td><td><b>Binding</b></td><td><b>Documentation</b></td></tr><tr><td>IN</td><td>_outputFormat</td><td/><td>0..1</td><td><a href=\"http://hl7.org/fhir/R4/datatypes.html#string\">string</a></td><td/><td><div><p>Support is required for a server, optional for a client.</p>\n<p>The format for the requested Bulk Data files to be generated as per <a href=\"http://hl7.org/fhir/R4/async.html\">FHIR Asynchronous Request Pattern</a>. Defaults to <code>application/fhir+ndjson</code>. The server SHALL support <a href=\"http://ndjson.org\">Newline Delimited JSON</a>, but MAY choose to support additional output formats. The server SHALL accept the full content type of <code>application/fhir+ndjson</code> as well as the abbreviated representations <code>application/ndjson</code> and <code>ndjson</code>.</p>\n</div></td></tr><tr><td>IN</td><td>_since</td><td/><td>0..1</td><td><a href=\"http://hl7.org/fhir/R4/datatypes.html#instant\">instant</a></td><td/><td><div><p>Support is required for a server, optional for a client.</p>\n<p>Resources will be included in the response if their state has changed after the supplied time (e.g., if <code>Resource.meta.lastUpdated</code> is later than the supplied <code>_since</code> time). A server MAY return additional resources modified prior to the supplied time if the resources belong to the patient compartment of a patient added to the group after the supplied time (this behavior SHOULD be clearly documented by the server). The server MAY return resources that are referenced by the resources being returned regardless of when the referenced resources were last updated. For resources where the server does not maintain a last updated time, the server MAY include these resources in a response irrespective of the <code>_since</code> value supplied by a client.</p>\n</div></td></tr><tr><td>IN</td><td>_type</td><td/><td>0..*</td><td><a href=\"http://hl7.org/fhir/R4/datatypes.html#string\">string</a></td><td/><td><div><p>Support is optional for a server and a client.</p>\n<p>A string of comma-delimited FHIR resource types.</p>\n<p>The response SHALL be filtered to only include resources of the specified resource types(s).</p>\n<p>If this parameter is omitted, the server SHALL return all supported resources within the scope of the client authorization, though implementations MAY limit the resources returned to specific subsets of FHIR, such as those defined in the <a href=\"http://www.hl7.org/fhir/us/core/\">US Core Implementation Guide</a>. For groups of patients, the <a href=\"https://www.hl7.org/fhir/compartmentdefinition-patient.html\">Patient Compartment</a> SHOULD be used as a point of reference for recommended resources to be returned. However, other resources outside of the Patient Compartment that are referenced by the resources being returned and would be helpful in interpreting the patient data MAY also be returned (such as Organization and Practitioner). When this behavior is supported, a server SHOULD document this support (for example, as narrative text, or by including a <a href=\"https://www.hl7.org/fhir/graphdefinition.html\">GraphDefinition Resource</a>).</p>\n<p>A server that is unable to support <code>_type</code> SHOULD return an error and FHIR <code>OperationOutcome</code> resource so the client can re-submit a request omitting the <code>_type</code> parameter. If the client explicitly asks for export of resources that the Bulk Data server doesn't support, or asks for only resource types that are outside the Patient Compartment, the server SHOULD return details via a FHIR <code>OperationOutcome</code> resource in an error response to the request. When a <code>Prefer: handling=lenient</code> header is included in the request, the server MAY process the request instead of returning an error.</p>\n<p>For example <code>_type=Observation</code> could be used to filter a given export response to return only FHIR <code>Observation</code> resources.</p>\n</div></td></tr><tr><td>IN</td><td>_elements</td><td/><td>0..*</td><td><a href=\"http://hl7.org/fhir/R4/datatypes.html#string\">string</a></td><td/><td><div><p>Experimental - support is optional for a server and a client.</p>\n<p>String of comma-delimited FHIR Elements.</p>\n<p>When provided, the server SHOULD omit unlisted, non-mandatory elements from the resources returned. Elements SHOULD be of the form <code>[resource type].[element name]</code> (e.g., <code>Patient.id</code>) or <code>[element name]</code> (e.g., <code>id</code>) and only root elements in a resource are permitted. If the resource type is omitted, the element SHOULD be returned for all resources in the response where it is applicable.</p>\n<p>A server is not obliged to return just the requested elements. A server SHOULD always return mandatory elements whether they are requested or not. A server SHOULD mark the resources with the tag <code>SUBSETTED</code> to ensure that the incomplete resource is not actually used to overwrite a complete resource.</p>\n<p>A server that is unable to support <code>_elements</code> SHOULD return an error and a FHIR <code>OperationOutcome</code> resource so the client can re-submit a request omitting the <code>_elements</code> parameter. When a <code>Prefer: handling=lenient</code> header is included in the request, the server MAY process the request instead of returning an error.</p>\n</div></td></tr><tr><td>IN</td><td>patient</td><td/><td>0..*</td><td><a href=\"http://hl7.org/fhir/R4/references.html#Reference\">Reference</a> (<a href=\"http://hl7.org/fhir/R4/patient.html\" title=\"http://hl7.org/fhir/StructureDefinition/Patient\">Patient</a>)</td><td/><td><div><p>Experimental - support is optional for a server and a client.</p>\n<p>This parameter is only valid in kickoff requests initiated through a HTTP POST request. When provided, the server SHALL NOT return resources in the patient compartments belonging to patients outside of this list. If a client requests patients who are not present on the server or are not members of the requested group, the server SHOULD return details via a FHIR <code>OperationOutcome</code> resource in an error response to the request.</p>\n<p>A server that is unable to support the <code>patient</code> parameter SHOULD return an error and FHIR <code>OperationOutcome</code> resource so the client can re-submit a request omitting the <code>patient</code> parameter. When a <code>Prefer: handling=lenient</code> header is included in the request, the server MAY process the request instead of returning an error.</p>\n</div></td></tr><tr><td>IN</td><td>includeAssociatedData</td><td/><td>0..*</td><td><a href=\"http://hl7.org/fhir/R4/datatypes.html#code\">code</a></td><td><a href=\"ValueSet-include-associated-data.html\">Include Associated Data Value Set</a> (Extensible)</td><td><div><p>Experimental - support is optional for a server and a client.</p>\n<p>String of comma-delimited values.</p>\n<p>When provided, a server with support for the parameter and requested values SHALL return or omit a pre-defined set of FHIR resources associated with the request.</p>\n<p>A server that is unable to support the requested <code>includeAssociatedData</code> values SHOULD return an error and a FHIR <code>OperationOutcome</code> resource so the client can re-submit a request that omits those values (for example, if a server does not retain provenance data). When a <code>Prefer: handling=lenient</code> header is included in the request, the server MAY process the request instead of returning an error.</p>\n<p>If multiple conflicting values are included, the server SHALL apply the least restrictive value (value that will return the largest dataset).</p>\n</div></td></tr><tr><td>IN</td><td>_typeFilter</td><td/><td>0..*</td><td><a href=\"http://hl7.org/fhir/R4/datatypes.html#string\">string</a></td><td/><td><div><p>Support is optional for a server and a client.</p>\n<p>String with a FHIR REST search query.</p>\n<p>When provided, a server with support for the parameter and requested search queries SHALL filter the data in the response for resource types referenced in the typeFilter expression to only include resources that meet the specified criteria. FHIR search result parameters such as <code>_include</code> and <code>_sort</code> SHALL NOT be used.</p>\n<p>A server unable to support the requested <code>_typeFilter</code> queries SHOULD return an error and FHIR <code>OperationOutcome</code> resource so the client can re-submit a request that omits those queries. When a <code>Prefer: handling=lenient</code> header is included in the request, the server MAY process the request instead of returning an error.</p>\n</div></td></tr></table></div>"
    },
    "extension": [
        {
            "url": "http://hl7.org/fhir/StructureDefinition/structuredefinition-wg",
            "valueCode": "fhir"
        }
    ],
    "url" : `${config.baseUrl}/fhir/OperationDefinition/GroupExport`,
    "base": "http://hl7.org/fhir/uv/bulkdata/OperationDefinition/group-export",
    "version": "2.0.0",
    "name": "GroupLevelExport",
    "title": "FHIR Bulk Data Group Level Export",
    "status": "active",
    "kind": "operation",
    "date": "2020-07-29",
    "publisher": "HL7 International / FHIR Infrastructure",
    "contact": [
        {
            "name": "HL7 International / FHIR Infrastructure",
            "telecom": [
                {
                    "system": "url",
                    "value": "http://www.hl7.org/Special/committees/fiwg"
                },
                {
                    "system": "email",
                    "value": "fhir@lists.HL7.org"
                }
            ]
        }
    ],
    "description": "FHIR Operation to obtain a detailed set of FHIR resources of diverse resource types pertaining to all members of the specified [Group](https://www.hl7.org/fhir/group.html). The FHIR server SHALL support invocation of this operation using the [FHIR Asynchronous Request Pattern](http://hl7.org/fhir/R4/async.html)",
    "jurisdiction": [
        {
            "coding": [
                {
                    "system": "http://unstats.un.org/unsd/methods/m49/m49.htm",
                    "code": "001"
                }
            ]
        }
    ],
    "code": "export",
    "resource": [
        "Group"
    ],
    "system": false,
    "type": false,
    "instance": true,
    "parameter": [
        {
            "name": "_outputFormat",
            "use": "in",
            "min": 0,
            "max": "1",
            "documentation": "The format for the requested Bulk Data files to be generated as per [FHIR Asynchronous Request Pattern](http://hl7.org/fhir/R4/async.html). Defaults to `application/fhir+ndjson`. The server also supports `application/ndjson`, `ndjson`, `text/csv`, and `csv`.",
            "type": "string"
        },
        {
            "name": "_since",
            "use": "in",
            "min": 0,
            "max": "1",
            "documentation": "Resources will be included in the response if their state has changed after the supplied time (e.g., if `Resource.meta.lastUpdated` is later than the supplied `_since` time).",
            "type": "instant"
        },
        {
            "name": "_type",
            "use": "in",
            "min": 0,
            "max": "*",
            "documentation": "A string of comma-delimited FHIR resource types.",
            "type": "string"
        },
        {
            "name": "_elements",
            "use": "in",
            "min": 0,
            "max": "*",
            "documentation": "Experimental - support is optional for a server and a client.",
            "type": "string"
        },
        {
            "name": "patient",
            "use": "in",
            "min": 0,
            "max": "*",
            "documentation": "Experimental - support is optional for a server and a client.\n\nThis parameter is only valid in kickoff requests initiated through a HTTP POST request. When provided, the server SHALL NOT return resources in the patient compartments belonging to patients outside of this list. If a client requests patients who are not present on the server or are not members of the requested group, the server SHOULD return details via a FHIR `OperationOutcome` resource in an error response to the request.\n\nA server that is unable to support the `patient` parameter SHOULD return an error and FHIR `OperationOutcome` resource so the client can re-submit a request omitting the `patient` parameter. When a `Prefer: handling=lenient` header is included in the request, the server MAY process the request instead of returning an error.",
            "type": "Reference",
            "targetProfile": [
                "http://hl7.org/fhir/StructureDefinition/Patient"
            ]
        },
        {
            "name": "_typeFilter",
            "use": "in",
            "min": 0,
            "max": "*",
            "documentation": "String with a FHIR REST search query. FHIR search result parameters such as `_include` and `_sort` SHALL NOT be used.",
            "type": "string"
        }
    ]
}