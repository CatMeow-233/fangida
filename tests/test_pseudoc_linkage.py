"""PLT 命名只使用 Loader 重定位与已完成指令快照。"""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from fangida.models import AnalysisResult
from fangida.plugins.pseudoc.linkage import resolve_linkage
from fangida.plugins.pseudoc.pipeline import populate_native_pseudoc
from tests.test_pseudoc import function, instruction as ins


def linked_result():
    caller = function(ins(0x1000,'mov','x0','#7',size=4),ins(0x1004,'b','#0x2000',size=4,kind='jump',target=0x2000),name='caller')
    thunk = [ins(0x2000,'adrp','x16','#0x3000',size=4),ins(0x2004,'ldr','x17','[x16','#0x18]',size=4),
             ins(0x2008,'add','x16','x16','#0x18',size=4),ins(0x200c,'br','x17',size=4,kind='jump')]
    return AnalysisResult('fixture','elf','kkagent','partial',functions=[caller],metadata={
        'architecture':'arm64','full_disassembly':thunk,'dynamic_relocations':[
            {'type':1026,'address':0x3018,'symbol_name':'sdk_operation','symbol_value':0x4000}]})


class PseudocodeLinkageTests(unittest.TestCase):
    def test_verified_plt_resolves_without_decoding_and_snapshot_is_immutable(self):
        result = linked_result()
        before = copy.deepcopy(result)
        with patch('fangida.processors.get_processor',side_effect=AssertionError('不得重新解码')):
            evidence = resolve_linkage(result)[0x2000]
        self.assertEqual(evidence['name'],'sdk_operation')
        self.assertEqual(evidence['got_address'],0x3018)
        self.assertEqual(evidence['runtime_binding'],'dynamic_and_possibly_preemptible')
        self.assertEqual(result,before)

    def test_missing_or_wrong_relocation_is_not_guessed_from_plt_layout(self):
        for relocations in ([],[{'type':1027,'address':0x3018,'symbol_name':'wrong'}],
                            [{'type':1026,'address':0x3010,'symbol_name':'wrong'}]):
            result = linked_result()
            result.metadata['dynamic_relocations'] = relocations
            self.assertEqual(resolve_linkage(result),{})

    def test_mismatched_add_target_register_or_instruction_boundary_is_rejected(self):
        for index, field, value in ((2,'operands',('x16','x16','#0x20')),
                                    (3,'operands',('x6',)),(1,'size',8),
                                    (0,'operands',('x16','#0x3001'))):
            result = linked_result()
            result.metadata['full_disassembly'][index][field] = value
            self.assertEqual(resolve_linkage(result),{})

    def test_conflicting_snapshot_or_relocation_is_unresolved(self):
        result = linked_result()
        duplicate = copy.deepcopy(result.metadata['full_disassembly'][1])
        duplicate['operands'] = ('x17','[x16','#0x20]')
        result.metadata['full_disassembly'].append(duplicate)
        self.assertEqual(resolve_linkage(result),{})
        result = linked_result()
        result.metadata['dynamic_relocations'].append({'type':1026,'address':0x3018,'symbol_name':'other'})
        self.assertEqual(resolve_linkage(result),{})

    def test_cancellation_and_budgets_do_not_return_partial_guesses(self):
        result = linked_result()
        self.assertEqual(resolve_linkage(result,is_cancelled=lambda:True),{})
        with patch('fangida.plugins.pseudoc.linkage.MAX_LINKAGE_ROWS',1):
            self.assertEqual(resolve_linkage(result),{})

    def test_pipeline_names_tail_transfer_and_does_not_infer_plt_prototype(self):
        result = linked_result()
        with patch('fangida.processors.get_processor',side_effect=AssertionError('不得重新解码')):
            populate_native_pseudoc(result)
        self.assertIn('tail_transfer(sdk_operation,',result.functions[0]['pseudoc'])
        self.assertIn('unknown_arguments()',result.functions[0]['pseudoc'])
        evidence = result.functions[0]['pseudoc_reconstruction']['calls'][0]
        self.assertEqual(evidence['target'],0x2000)
        self.assertFalse(evidence['argument_count_known'])
        self.assertEqual(result.metadata['pseudoc_linkage'][0]['name'],'sdk_operation')


if __name__ == '__main__': unittest.main()
