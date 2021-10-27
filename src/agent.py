from forta_agent import Finding, FindingType, FindingSeverity

COMPOUND_CONTRACTS = {
    "0xc00e94Cb662C3520282E6f5717214004A7f26888":"Compound",
    "0x4ddc2d193948926d02f9b1fe9e1daa0718270ed5":"Compound Ether",
    "0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643":"Compound Dai",
    "0x39aa39c021dfbae8fac545936693ac917d5e7563":"Compound USD Coin",
    "0xf650c3d88d12db855b8bf7d11be6c55a4e07dcc9":"Compound USDT",
    "0xb3319f5d18bc0d84dd1b4825dcde5d5f7266d407":"Compound 0x",
    "0x6c8c6b02e7b2be14d4fa6022dfd6d75921d90e4e":"Compound Basic Attention Token",
    "0xC11b1268C1A384e55C48c2391d8d480264A3A7F4":"Compound Wrapped BTC",
    "0x70e36f6BF80a52b3B46b3aF8e106CC0ed743E8e4":"Compound Collateral",
    "0x35A18000230DA775CAc24873d00Ff85BccdeD550":"Compound Uniswap",
}
blacklist = set()

def initialize():
    # Add black list addresses in this set
    # For the sake of demo, I picked up random addresses from the log
    # TODO: Retrieve the blacklist from separated file or external database
    global blacklist
    blacklist = {
        "0x84fe4e963648c623a0ba762daa11ab3635434626",
        "0x108a8e6fd2b96b297d1ecbf17e4b6f29f26cb17e"
    }

def handle_transaction(transaction_event):
    findings = []

    # Check only Compound contracts
    contract_address = None
    contract_name = None
    for addr, name in COMPOUND_CONTRACTS.items():
        if addr in transaction_event.addresses.keys():
            contract_address = addr
            contract_name = name
            break

    if not contract_address or not contract_name:
        return findings

    # Check if address is blacklisted
    reporeted = set()
    for address, _ in transaction_event.addresses.items(): 
        # Check if address is in the blacklist, but not reposted yet
        # I believe addresses doesn't have duplicates, but just in case
        if True and address in blacklist and address not in reporeted:
            reporeted.add(address)
            findings.append(Finding({
                'name': 'Blacklisted Address Detected',
                'description': f'Blacklisted Address {address} interacted with {contract_address}',
                'alert_id': 'COMP-BLACK-1',
                'type': FindingType.Suspicious,
                'severity': FindingSeverity.High,
                'metadata': {
                    'contract_address': contract_address,
                    'contract_name': contract_name,
                    'from': transaction_event.from_,
                    'to': transaction_event.to,
                    'block_number': transaction_event.block_number,
                    'block_hash': transaction_event.block_hash,
                    'timestamp': transaction_event.timestamp,
                }
            }))

    return findings


