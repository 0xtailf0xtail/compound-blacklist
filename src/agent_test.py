from forta_agent import FindingSeverity, FindingType, create_transaction_event
from agent import handle_transaction, initialize
import time

class TestCompoundBlackListAgent:
    def test_returns_empty_findings_if_transaction_is_not_compound(self):
        tx_event = create_transaction_event(
            {'addresses': 
                {
                    '0x0001': True,
                    '0x0002': True
                }
            })

        initialize()
        findings = handle_transaction(tx_event)

        assert len(findings) == 0

    def test_returns_empty_findings_if_blacklisted_address_is_not_detected(self):
        tx_event = create_transaction_event(
            {'addresses': 
                {
                  '0x0001': True,
                  '0xc00e94Cb662C3520282E6f5717214004A7f26888': True # compound address
                }
            })

        initialize()
        findings = handle_transaction(tx_event)

        assert len(findings) == 0

    def test_returns_one_finding_if_one_blacklisted_address_is_detected(self):
        blacklisted_address = '0x84fe4e963648c623a0ba762daa11ab3635434626'
        contract_address = '0xc00e94Cb662C3520282E6f5717214004A7f26888'
        block_number = 12345
        block_hash = '0x2345'
        timestamp = time.time()
        tx_event = create_transaction_event(
            {
                'addresses': {
                    blacklisted_address: True, 
                    contract_address: True
                },
                'transaction': {
                    'from': contract_address,
                    'to': blacklisted_address,
                },
                'block': {
                    'number': block_number,
                    'hash': block_hash,
                    'timestamp': timestamp,
                }
            })

        initialize()
        findings = handle_transaction(tx_event)

        assert len(findings) == 1

        finding = findings[0]
        assert finding.name == "Blacklisted Address Detected"
        assert finding.description == f'Blacklisted Address {blacklisted_address} interacted with {contract_address}'
        assert finding.alert_id == 'COMP-BLACK-1'
        assert finding.type == FindingType.Suspicious
        assert finding.severity == FindingSeverity.High
        assert finding.metadata['contract_address'] == contract_address
        assert finding.metadata['contract_name'] == 'Compound'
        assert finding.metadata['from'] == contract_address
        assert finding.metadata['to'] == blacklisted_address
        assert finding.metadata['block_number'] == block_number
        assert finding.metadata['block_hash'] == block_hash
        assert finding.metadata['timestamp'] == timestamp

    def test_returns_two_findings_if_two_blacklisted_address_is_detected(self):
        blacklisted_address_1 = "0x84fe4e963648c623a0ba762daa11ab3635434626"
        blacklisted_address_2 = "0x108a8e6fd2b96b297d1ecbf17e4b6f29f26cb17e"
        contract_address = "0xc00e94Cb662C3520282E6f5717214004A7f26888"
        block_number = 12345
        block_hash = '0x2345'
        timestamp = time.time()
        tx_event = create_transaction_event(
            {
                'addresses': {
                    blacklisted_address_1: True, 
                    blacklisted_address_2: True,
                    contract_address: True
                },
                'transaction': {
                    'from': contract_address,
                    'to': blacklisted_address_1,
                },
                'block': {
                    'number': block_number,
                    'hash': block_hash,
                    'timestamp': timestamp,
                }
            })

        initialize()
        findings = handle_transaction(tx_event)

        assert len(findings) == 2

        finding = findings[0]
        assert finding.name == "Blacklisted Address Detected"
        assert finding.description == f'Blacklisted Address {blacklisted_address_1} interacted with {contract_address}'
        assert finding.alert_id == 'COMP-BLACK-1'
        assert finding.type == FindingType.Suspicious
        assert finding.severity == FindingSeverity.High
        assert finding.metadata['contract_address'] == contract_address
        assert finding.metadata['contract_name'] == 'Compound'
        assert finding.metadata['from'] == contract_address
        assert finding.metadata['to'] == blacklisted_address_1
        assert finding.metadata['block_number'] == block_number
        assert finding.metadata['block_hash'] == block_hash
        assert finding.metadata['timestamp'] == timestamp

        finding = findings[1]
        assert finding.name == "Blacklisted Address Detected"
        assert finding.description == f'Blacklisted Address {blacklisted_address_2} interacted with {contract_address}'
        assert finding.alert_id == 'COMP-BLACK-1'
        assert finding.type == FindingType.Suspicious
        assert finding.severity == FindingSeverity.High
        assert finding.metadata['contract_address'] == contract_address
        assert finding.metadata['contract_name'] == 'Compound'
        assert finding.metadata['from'] == contract_address
        assert finding.metadata['to'] == blacklisted_address_1
        assert finding.metadata['block_number'] == block_number
        assert finding.metadata['block_hash'] == block_hash
        assert finding.metadata['timestamp'] == timestamp