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
if sys.version_info[0] < 3 or sys.version_info[0] == 3 \
        and sys.version_info[1] < 4:
    from mock import patch, call, Mock, DEFAULT
else:
    from unittest.mock import patch, call, Mock, DEFAULT

pbm = "awslimitchecker.services.cloudfront"  # module patch base
pb = "%s._CloudfrontService" % pbm  # class patch pase


class Test_CloudfrontService(object):
    def test_init(self):
        """test __init__()"""
        cls = _CloudfrontService(21, 43, {}, None)
        assert cls.service_name == "CloudFront"
        assert cls.api_name == "cloudfront"
        assert cls.quotas_service_code == "cloudfront"
        assert cls.conn is None
        assert cls.warning_threshold == 21
        assert cls.critical_threshold == 43

    def test_get_limits(self):
        cls = _CloudfrontService(21, 43, {}, None)
        cls.limits = {}
        res = cls.get_limits()
        assert sorted(res.keys()) == sorted(
            [
                "Alternate domain names (CNAMEs) per distribution",
                "Cache behaviors per distribution",
                "Distributions per AWS account",
                "Origins per distribution",
                "Origin groups per distribution"
            ]
        )
        for name, limit in res.items():
            assert limit.service == cls
            assert limit.def_warning_threshold == 21
            assert limit.def_critical_threshold == 43

    def test_get_limits_again(self):
        """test that existing limits dict is returned on subsequent calls"""
        mock_limits = Mock()
        cls = _CloudfrontService(21, 43, {}, None)
        cls.limits = mock_limits
        res = cls.get_limits()
        assert res == mock_limits

    def test_find_usage(self):
        """
        Check that find_usage() method calls other methods.
        """
        with patch.multiple(
            pb,
            connect=DEFAULT,
            _find_usage_distributions=DEFAULT,
            autospec=True
        ) as mocks:
            cls = _CloudfrontService(21, 43, {}, None)
            assert cls._have_usage is False
            cls.find_usage()

        assert cls._have_usage is True
        assert len(mocks) == 2
        # other methods should have been called
        for x in [
            "_find_usage_distributions",
        ]:
            assert mocks[x].mock_calls == [call(cls)]

    def test_find_usage_distributions(self):
        """
        Check that obtaining distributions usage is correct, by mocking AWS
        response.
        """
        response = result_fixtures.CloudFront.test_find_usage_distributions

        mock_conn = Mock()

        # with patch("%s.connect" % pb) as mock_connect:
        with patch("%s.paginate_dict" % pbm) as mock_paginate:
            cls = _CloudfrontService(21, 43, {}, None)
            cls.conn = mock_conn
            mock_paginate.return_value = response
            cls._find_usage_distributions()

        expected_nb_distributions = len(
            response['DistributionList']['Items'])

        # Check that usage values are correctly set
        assert len(
            cls.limits["Distributions per AWS account"].get_current_usage()
        ) == 1
        assert (
            cls.limits["Distributions per AWS account"].get_current_usage()[0]
            .get_value() == expected_nb_distributions
        )
        assert (
            cls.limits["Distributions per AWS account"].get_current_usage()[0]
            .resource_id is None
        )

        assert len(cls.limits[
            "Alternate domain names (CNAMEs) per distribution"
        ].get_current_usage()) == expected_nb_distributions
        assert cls.limits[
            "Alternate domain names (CNAMEs) per distribution"
        ].get_current_usage()[0].get_value() == 3
        assert cls.limits[
            "Alternate domain names (CNAMEs) per distribution"
        ].get_current_usage()[0].resource_id == "ID-DISTRIBUTION-000"

        assert len(cls.limits[
            "Cache behaviors per distribution"
        ].get_current_usage()) == expected_nb_distributions
        assert cls.limits[
            "Cache behaviors per distribution"
        ].get_current_usage()[1].resource_id == "ID-DISTRIBUTION-001"
        assert cls.limits[
            "Cache behaviors per distribution"
        ].get_current_usage()[1].get_value() == 4

        assert len(cls.limits[
            "Origins per distribution"
        ].get_current_usage()) == expected_nb_distributions
        assert cls.limits[
            "Origins per distribution"
        ].get_current_usage()[2].resource_id == "ID-DISTRIBUTION-002"
        assert cls.limits[
            "Origins per distribution"
        ].get_current_usage()[2].get_value() == 3

        assert len(cls.limits[
            "Origin groups per distribution"
        ].get_current_usage()) == expected_nb_distributions
        assert cls.limits[
            "Origin groups per distribution"
        ].get_current_usage()[3].resource_id == "ID-DISTRIBUTION-003"
        assert cls.limits[
            "Origin groups per distribution"
        ].get_current_usage()[3].get_value() == 1

        # Check which methods were called
        assert mock_conn.mock_calls == []
        # assert mock_connect.mock_calls == [call()]
        assert mock_paginate.mock_calls == [
            call(
                mock_conn.list_distributions,
                alc_marker_path=["DistributionList", "NextMarker"],
                alc_data_path=["DistributionList", "Items"],
                alc_marker_param="Marker",
            )
        ]

    def test_find_usage_distributions_empty(self):
        """
        Check that obtaining distributions usage is correct, by mocking AWS
        response.
        Case when there are no distributions.
        """
        resp = result_fixtures.CloudFront.test_find_usage_distributions_empty

        mock_conn = Mock()

        # with patch("%s.connect" % pb) as mock_connect:
        with patch("%s.paginate_dict" % pbm) as mock_paginate:
            cls = _CloudfrontService(21, 43, {}, None)
            cls.conn = mock_conn
            mock_paginate.return_value = resp
            cls._find_usage_distributions()

        # Check that usage values are correctly set
        assert len(
            cls.limits["Distributions per AWS account"].get_current_usage()
        ) == 1
        assert (
            cls.limits["Distributions per AWS account"].get_current_usage()[0]
            .get_value() == 0
        )
        assert (
            cls.limits["Distributions per AWS account"].get_current_usage()[0]
            .resource_id is None
        )

    def test_required_iam_permissions(self):
        cls = _CloudfrontService(21, 43, {}, None)
        assert cls.required_iam_permissions() == [
            "cloudfront:ListDistributions"
        ]
