"""
awslimitchecker/tests/services/test_cloudfront.py

The latest version of this package is available at:
<https://github.com/jantman/awslimitchecker>

################################################################################
Copyright 2015-2018 Jason Antman <jason@jasonantman.com>

    This file is part of awslimitchecker, also known as awslimitchecker.

    awslimitchecker is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    awslimitchecker is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with awslimitchecker.  If not, see <http://www.gnu.org/licenses/>.

The Copyright and Authors attributions contained herein may not be removed or
otherwise altered, except to add the Author attribution of a contributor to
this work. (Additional Terms pursuant to Section 7b of the AGPL v3)
################################################################################
While not legally required, I sincerely request that anyone who finds
bugs please submit them at <https://github.com/jantman/awslimitchecker> or
to me via email, and that you send any contributions or improvements
either as a pull request on GitHub, or to me via email.
################################################################################

AUTHORS:
Jason Antman <jason@jasonantman.com> <http://www.jasonantman.com>
################################################################################
"""

import sys
from awslimitchecker.tests.services import result_fixtures
from awslimitchecker.services.cloudfront import _CloudfrontService

# https://code.google.com/p/mock/issues/detail?id=249
# py>=3.4 should use unittest.mock not the mock package on pypi
if (
        sys.version_info[0] < 3 or
        sys.version_info[0] == 3 and sys.version_info[1] < 4
):
    from mock import patch, call, Mock
else:
    from unittest.mock import patch, call, Mock


pbm = 'awslimitchecker.services.cloudfront'  # module patch base
pb = '%s._CloudfrontService' % pbm  # class patch pase


class Test_CloudfrontService(object):

    def test_init(self):
        """test __init__()"""
        cls = _CloudfrontService(21, 43)
        assert cls.service_name == 'CloudFront'
        assert cls.api_name == 'cloudfront'
        assert cls.quotas_service_code == 'cloudfront'
        assert cls.conn is None
        assert cls.warning_threshold == 21
        assert cls.critical_threshold == 43

    def test_get_limits(self):
        cls = _CloudfrontService(21, 43)
        cls.limits = {}
        res = cls.get_limits()
        assert sorted(res.keys()) == sorted([
            'SomeLimitNameHere',
            'Alternate domain names (CNAMEs) per distributionGlobal',
            'Cache behaviors per distributionGlobal',
            'Concurrent executionsGlobal',
            'Cookies per cache policyGlobal',
            'Cookies per origin request policyGlobal',
            'Custom headers: maximum number of custom headers that you can configure CloudFront to add to origin requestsGlobal',
            'Data transfer rate per distributionGlobal',
            'Distributions associated with a single key groupGlobal',
            'Distributions per AWS account that you can create triggers forGlobal',
            'Headers per cache policyGlobal',
            'Headers per origin request policyGlobal',
            'Key groups associated with a single distributionGlobal',
            'Key groups per AWS accountGlobal',
            'Origin access identities per accountGlobal',
            'Origin groups per distributionGlobal',
            'Origins per distributionGlobal',
            'Public keys in a single key groupGlobal',
            'Query strings per cache policyGlobal',
            'Query strings per origin request policyGlobal',
            'RTMP distributions per AWS accountGlobal',
            'Request timeoutGlobal',
            'Requests per secondGlobal',
            'Requests per second per distributionGlobal',
            'Response timeout per originGlobal',
            'SSL certificates per AWS account when serving HTTPS requests using dedicated IP addressesGlobal',
            'Triggers per distributionGlobal',
            'Web distributions per AWS accountGlobal',
            'Whitelisted cookies per cache behaviorGlobal',
            'Whitelisted headers per cache behaviorGlobal',
            'Whitelisted query strings per cache behaviorGlobal',
        ])
        for name, limit in res.items():
            assert limit.service == cls
            assert limit.def_warning_threshold == 21
            assert limit.def_critical_threshold == 43

    def test_get_limits_again(self):
        """test that existing limits dict is returned on subsequent calls"""
        mock_limits = Mock()
        cls = _CloudfrontService(21, 43)
        cls.limits = mock_limits
        res = cls.get_limits()
        assert res == mock_limits

    def test_find_usage(self):
        # put boto3 responses in response_fixtures.py, then do something like:
        # response = result_fixtures.EBS.test_find_usage_ebs
        mock_conn = Mock()
        mock_conn.some_method.return_value =  # some logical return value
        with patch('%s.connect' % pb) as mock_connect:
            cls = _CloudfrontService(21, 43)
            cls.conn = mock_conn
            assert cls._have_usage is False
            cls.find_usage()
        assert mock_connect.mock_calls == [call()]
        assert cls._have_usage is True
        assert mock_conn.mock_calls == [call.some_method()]
        # TODO - assert about usage

    def test_required_iam_permissions(self):
        cls = _CloudfrontService(21, 43)
        assert cls.required_iam_permissions() == [
            # TODO - permissions here
        ]
