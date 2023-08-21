import json
from compatibility.json import Encoder as CompatEncoder
from androguard.core.bytecode import TmpBlock


def method2json_direct(mx):
    """

    :param mx: :class:`~androguard.core.analysis.analysis.MethodAnalysis`
    :return:
    """
    d = {}
    reports = []
    d["reports"] = reports

    hooks = {}

    l = []
    for DVMBasicMethodBlock in mx.basic_blocks.gets():
        for index, DVMBasicMethodBlockChild in enumerate(
                DVMBasicMethodBlock.childs):
            if DVMBasicMethodBlock.get_name(
            ) == DVMBasicMethodBlockChild[-1].get_name():

                preblock = TmpBlock(DVMBasicMethodBlock.get_name() + "-pre")

                cnblock = {
                    "BasicBlockId": DVMBasicMethodBlock.get_name() + "-pre",
                    "start": DVMBasicMethodBlock.start,
                    "notes": [],
                    "Edge": [DVMBasicMethodBlock.get_name()],
                    "registers": 0,
                    "instructions": [],
                    "info_bb": 0
                }

                l.append(cnblock)

                for parent in DVMBasicMethodBlock.fathers:
                    hooks[parent[-1].get_name()] = []
                    hooks[parent[-1].get_name()].append(preblock)

                    for idx, child in enumerate(parent[-1].childs):
                        if child[-1].get_name(
                        ) == DVMBasicMethodBlock.get_name():
                            hooks[parent[-1].get_name()].append(child[-1])

    for DVMBasicMethodBlock in mx.basic_blocks.gets():
        cblock = {
            "BasicBlockId": DVMBasicMethodBlock.get_name(),
            "start": DVMBasicMethodBlock.start,
            "notes": DVMBasicMethodBlock.get_notes(),
            "registers": mx.get_method().get_code().get_registers_size(),
            "instructions": []
        }

        ins_idx = DVMBasicMethodBlock.start
        last_instru = None
        for DVMBasicMethodBlockInstruction in DVMBasicMethodBlock.get_instructions(
        ):
            c_ins = {
                "idx": ins_idx,
                "name": DVMBasicMethodBlockInstruction.get_name(),
                "operands":
                DVMBasicMethodBlockInstruction.get_operands(ins_idx),
            }

            cblock["instructions"].append(c_ins)

            if (DVMBasicMethodBlockInstruction.get_op_value() == 0x2b
                    or DVMBasicMethodBlockInstruction.get_op_value() == 0x2c):
                values = DVMBasicMethodBlock.get_special_ins(ins_idx)
                cblock["info_next"] = values.get_values()

            ins_idx += DVMBasicMethodBlockInstruction.get_length()
            last_instru = DVMBasicMethodBlockInstruction

        cblock["info_bb"] = 0
        if DVMBasicMethodBlock.childs:
            if len(DVMBasicMethodBlock.childs) > 1:
                cblock["info_bb"] = 1

            if (last_instru.get_op_value() == 0x2b
                    or last_instru.get_op_value() == 0x2c):
                cblock["info_bb"] = 2

        cblock["Edge"] = []
        for DVMBasicMethodBlockChild in DVMBasicMethodBlock.childs:
            ok = False
            if DVMBasicMethodBlock.get_name() in hooks:
                if DVMBasicMethodBlockChild[-1] in hooks[
                        DVMBasicMethodBlock.get_name()]:
                    ok = True
                    cblock["Edge"].append(
                        hooks[DVMBasicMethodBlock.get_name()][0].get_name())

            if not ok:
                cblock["Edge"].append(DVMBasicMethodBlockChild[-1].get_name())

        exception_analysis = DVMBasicMethodBlock.get_exception_analysis()
        if exception_analysis:
            cblock["Exceptions"] = exception_analysis.get()

        reports.append(cblock)

    reports.extend(l)

    return json.dumps(d, cls=CompatEncoder)
