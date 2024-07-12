<!--
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2023 ForgeRock AS.
-->
# Fingerprint Nodes

The Fingerprint Profiler and Fingerprint Response nodes let you integrate your Advanced Identity Cloud environment with the Fingerprint platform to help reduce fraud and improve customer experience. The integration with Fingerprint provides browser fingerprinting directly from an authentication journey with high confidence, at an average score of 99.5%.

When you identify browsers or devices with Fingerprint, you get back the visitorId value. You can use this value in your business logic to find suspicious activity or for marketing analytics. In some cases you do not want the client devices receive visitorID value from Fingerprint. Instead, you can receive a random requestID that can be used in business logic. This mode of not sending back visitorID is called Zero Trust Mode (ZTM).

You must Setup the prerequisites on the Fingerprint site before you can use Fingerprint nodes.

Advanced Identity Cloud provides two authentication nodes for Fingerprint authentication journeys:

Fingerprint Profiler node

Fingerprint Response node

## Fingerprint Profiler node

The Fingerprint Profiler node injects the client-side Javascript code required for the fingerprinting process.

Configuration
Property	Usage
Public API Key

Public API key for the Fingerprint application.

Script URL Pattern

URL path to a hosted JavaScript when using a custom domain. The default URL pattern is https://fpjscdn.net/v3.

Endpoint (optional)

URL path to the endpoint address when using a custom domain. This is an optional property.

Fingerprint Region

The Fingerprint region in which the Fingerprint application is set up. To use the US or the default region, specify GLOBAL.

Shared State VisitorID

Name of the shared state variable to store the device fingerprint. When ZTM is enabled, set the same value in the Fingerprint Response node.

Zero Trust Mode

You can enable ZTM if your application is set up in ZTM, and the Fingerprint Response node is configured to deliver the fingerprint.

## Fingerprint Response node
The Fingerprint Response node is used in the zero-trust model to fetch the fingerprint and server-side confidence score.

Configuration
The configurable properties for this node are:

Property	Usage
Secret API Key

Secret API key configured on the Fingerprint site.

Events API URL

Path to an events API. The default is https://eu.api.fpjs.io/events/. Other options include:

https://api.fpjs.io/events/

https://ap.api.fpjs.io/events/

Shared State VisitorID

Name of the shared state variable to store the fingerprint. This should be the same as in the Fingerprint Profile node.

Get full response payload

Disabled by default. Enable if you want to store the full fingerprint API response in shared state.

Shared State Response

Name of the variable to store the fingerprint API response. Used only when Get full response payload is enabled.

