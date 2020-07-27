/*******************************************************************************
 * Copyright (c) 2018, 2020 IBM Corp. and others
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution and is available at http://eclipse.org/legal/epl-2.0
 * or the Apache License, Version 2.0 which accompanies this distribution
 * and is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License, v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception [1] and GNU General Public
 * License, version 2 with the OpenJDK Assembly Exception [2].
 *
 * [1] https://www.gnu.org/software/classpath/license.html
 * [2] http://openjdk.java.net/legal/assembly-exception.html
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0 WITH Classpath-exception-2.0 OR LicenseRef-GPL-2.0 WITH Assembly-exception
 *******************************************************************************/

#include <stddef.h>
#include "codegen/ARM64Instruction.hpp"
#include "codegen/BackingStore.hpp"
#include "codegen/CodeGenerator.hpp"
#include "codegen/GenerateInstructions.hpp"
#include "codegen/Instruction.hpp"
#include "codegen/MemoryReference.hpp"
#include "codegen/RealRegister.hpp"
#include "codegen/RegisterDependency.hpp"
#include "il/Node.hpp"
#include "il/Node_inlines.hpp"

// Replace this by #include "codegen/Instruction.hpp" when available for aarch64
namespace TR { class Instruction; }

OMR::ARM64::RegisterDependencyConditions::RegisterDependencyConditions(
                                       TR::CodeGenerator *cg,
                                       TR::Node          *node,
                                       uint32_t          extranum,
                                       TR::Instruction  **cursorPtr)
   {
   List<TR::Register>  regList(cg->trMemory());
   TR::Instruction    *iCursor = (cursorPtr==NULL)?NULL:*cursorPtr;
   int32_t totalNum = node->getNumChildren() + extranum;
   int32_t i;

   cg->comp()->incVisitCount();

   _preConditions = new (totalNum, cg->trMemory()) TR_ARM64RegisterDependencyGroup;
   _postConditions = new (totalNum, cg->trMemory()) TR_ARM64RegisterDependencyGroup;
   _numPreConditions = totalNum;
   _addCursorForPre = 0;
   _numPostConditions = totalNum;
   _addCursorForPost = 0;

   // First, handle dependencies that match current association
   for (i = 0; i < node->getNumChildren(); i++)
      {
      TR::Node *child = node->getChild(i);
      TR::Register *reg = child->getRegister();
      TR::RealRegister::RegNum regNum = (TR::RealRegister::RegNum)cg->getGlobalRegister(child->getGlobalRegisterNumber());

      if (reg->getAssociation() != regNum)
         {
         continue;
         }

      addPreCondition(reg, regNum);
      addPostCondition(reg, regNum);
      regList.add(reg);
      }

   // Second pass to handle dependencies for which association does not exist
   // or does not match
   for (i = 0; i < node->getNumChildren(); i++)
      {
      TR::Node *child = node->getChild(i);
      TR::Register *reg = child->getRegister();
      TR::Register *copyReg = NULL;
      TR::RealRegister::RegNum regNum = (TR::RealRegister::RegNum)cg->getGlobalRegister(child->getGlobalRegisterNumber());

      if (reg->getAssociation() == regNum)
         {
         continue;
         }

      if (regList.find(reg))
         {
         TR_RegisterKinds kind = reg->getKind();

         TR_ASSERT_FATAL((kind == TR_GPR) || (kind == TR_FPR), "Invalid register kind.");

         if (kind == TR_GPR)
            {
            bool containsInternalPointer = reg->getPinningArrayPointer();
            copyReg = (reg->containsCollectedReference() && !containsInternalPointer) ?
                        cg->allocateCollectedReferenceRegister() : cg->allocateRegister();
            if (containsInternalPointer)
               {
               copyReg->setContainsInternalPointer();
               copyReg->setPinningArrayPointer(reg->getPinningArrayPointer());
               }
            iCursor = generateMovInstruction(cg, node, copyReg, reg, true, iCursor);
            }
         else
            {
            bool isSinglePrecision = reg->isSinglePrecision();
            copyReg = isSinglePrecision ? cg->allocateSinglePrecisionRegister() : cg->allocateRegister(TR_FPR);
            iCursor = generateTrg1Src1Instruction(cg, isSinglePrecision ? TR::InstOpCode::fmovs : TR::InstOpCode::fmovd, node, copyReg, reg, iCursor);
            }

         reg = copyReg;
         }

      addPreCondition(reg, regNum);
      addPostCondition(reg, regNum);
      if (copyReg != NULL)
         {
         cg->stopUsingRegister(copyReg);
         }
      else
         {
         regList.add(reg);
         }
      }

   if (iCursor != NULL && cursorPtr != NULL)
      {
      *cursorPtr = iCursor;
      }
   }

void OMR::ARM64::RegisterDependencyConditions::unionNoRegPostCondition(TR::Register *reg, TR::CodeGenerator *cg)
   {
   addPostCondition(reg, TR::RealRegister::NoReg);
   }

bool OMR::ARM64::RegisterDependencyConditions::refsRegister(TR::Register *r)
   {
   for (uint16_t i = 0; i < _addCursorForPre; i++)
      {
      if (_preConditions->getRegisterDependency(i)->getRegister() == r &&
          _preConditions->getRegisterDependency(i)->getRefsRegister())
         {
         return true;
         }
      }
   for (uint16_t j = 0; j < _addCursorForPost; j++)
      {
      if (_postConditions->getRegisterDependency(j)->getRegister() == r &&
          _postConditions->getRegisterDependency(j)->getRefsRegister())
         {
         return true;
         }
      }
   return false;
   }

bool OMR::ARM64::RegisterDependencyConditions::defsRegister(TR::Register *r)
   {
   for (uint16_t i = 0; i < _addCursorForPre; i++)
      {
      if (_preConditions->getRegisterDependency(i)->getRegister() == r &&
          _preConditions->getRegisterDependency(i)->getDefsRegister())
         {
         return true;
         }
      }
   for (uint16_t j = 0; j < _addCursorForPost; j++)
      {
      if (_postConditions->getRegisterDependency(j)->getRegister() == r &&
          _postConditions->getRegisterDependency(j)->getDefsRegister())
         {
         return true;
         }
      }
   return false;
   }

bool OMR::ARM64::RegisterDependencyConditions::defsRealRegister(TR::Register *r)
   {
   for (uint16_t i = 0; i < _addCursorForPre; i++)
      {
      if (_preConditions->getRegisterDependency(i)->getRegister()->getAssignedRegister() == r &&
          _preConditions->getRegisterDependency(i)->getDefsRegister())
         {
         return true;
         }
      }
   for (uint16_t j = 0; j < _addCursorForPost; j++)
      {
      if (_postConditions->getRegisterDependency(j)->getRegister()->getAssignedRegister() == r &&
          _postConditions->getRegisterDependency(j)->getDefsRegister())
         {
         return true;
         }
      }
   return false;
   }

bool OMR::ARM64::RegisterDependencyConditions::usesRegister(TR::Register *r)
   {
   for (uint16_t i = 0; i < _addCursorForPre; i++)
      {
      if (_preConditions->getRegisterDependency(i)->getRegister() == r &&
          _preConditions->getRegisterDependency(i)->getUsesRegister())
         {
         return true;
         }
      }
   for (uint16_t j = 0; j < _addCursorForPost; j++)
      {
      if (_postConditions->getRegisterDependency(j)->getRegister() == r &&
          _postConditions->getRegisterDependency(j)->getUsesRegister())
         {
         return true;
         }
      }
   return false;
   }

void OMR::ARM64::RegisterDependencyConditions::bookKeepingRegisterUses(TR::Instruction *instr, TR::CodeGenerator *cg)
   {
   for (int i = 0; i < _addCursorForPre; i++)
      {
      instr->useRegister(_preConditions->getRegisterDependency(i)->getRegister());
      }
   for (int j = 0; j < _addCursorForPost; j++)
      {
      instr->useRegister(_postConditions->getRegisterDependency(j)->getRegister());
      }
   }

TR::RegisterDependencyConditions *
OMR::ARM64::RegisterDependencyConditions::clone(
   TR::CodeGenerator *cg,
   TR::RegisterDependencyConditions *added,
   bool omitPre, bool omitPost)
   {
   int preNum = omitPre ? 0 : getAddCursorForPre();
   int postNum = omitPost ? 0 : getAddCursorForPost();
   int addPreNum = 0;
   int addPostNum = 0;

   if (added != NULL)
      {
      addPreNum = omitPre ? 0 : added->getAddCursorForPre();
      addPostNum = omitPost ? 0 : added->getAddCursorForPost();
      }
   
   TR::RegisterDependencyConditions *result =  new (cg->trHeapMemory()) TR::RegisterDependencyConditions(preNum + addPreNum, postNum + addPostNum, cg->trMemory());
   for (int i = 0; i < preNum; i++)
      {
      auto singlePair = getPreConditions()->getRegisterDependency(i);
      result->addPreCondition(singlePair->getRegister(), singlePair->getRealRegister(), singlePair->getFlags());
      }

   for (int i = 0; i < postNum; i++)
      {
      auto singlePair = getPostConditions()->getRegisterDependency(i);
      result->addPostCondition(singlePair->getRegister(), singlePair->getRealRegister(), singlePair->getFlags());
      }

   for (int i = 0; i < addPreNum; i++)
      {
      auto singlePair = added->getPreConditions()->getRegisterDependency(i);
      result->addPreCondition(singlePair->getRegister(), singlePair->getRealRegister(), singlePair->getFlags());
      }

   for (int i = 0; i < addPostNum; i++)
      {
      auto singlePair = added->getPostConditions()->getRegisterDependency(i);
      result->addPostCondition(singlePair->getRegister(), singlePair->getRealRegister(), singlePair->getFlags());
      }

   return result;
   }

void TR_ARM64RegisterDependencyGroup::assignRegisters(
                        TR::Instruction *currentInstruction,
                        TR_RegisterKinds kindToBeAssigned,
                        uint32_t numberOfRegisters,
                        TR::CodeGenerator *cg)
   {
   TR::Compilation *comp = cg->comp();
   TR::Machine *machine = cg->machine();
   TR::Register  *virtReg;
   TR::RealRegister::RegNum dependentRegNum;
   TR::RealRegister *dependentRealReg, *assignedRegister;
   uint32_t i, j;
   bool changed;

   if (!comp->getOption(TR_DisableOOL))
      {
      for (i = 0; i< numberOfRegisters; i++)
         {
         virtReg = _dependencies[i].getRegister();
         dependentRegNum = _dependencies[i].getRealRegister();
         if (dependentRegNum == TR::RealRegister::SpilledReg)
            {
            TR_ASSERT(virtReg->getBackingStorage(),"should have a backing store if dependentRegNum == spillRegIndex()\n");
            if (virtReg->getAssignedRealRegister())
               {
               // this happens when the register was first spilled in main line path then was reverse spilled
               // and assigned to a real register in OOL path. We protected the backing store when doing
               // the reverse spill so we could re-spill to the same slot now
               traceMsg (comp,"\nOOL: Found register spilled in main line and re-assigned inside OOL");
               TR::Node *currentNode = currentInstruction->getNode();
               TR::RealRegister *assignedReg = toRealRegister(virtReg->getAssignedRegister());
               TR::MemoryReference *tempMR = new (cg->trHeapMemory()) TR::MemoryReference(currentNode, (TR::SymbolReference*)virtReg->getBackingStorage()->getSymbolReference(), cg);
               TR_RegisterKinds rk = virtReg->getKind();
               TR::InstOpCode::Mnemonic opCode;
               switch (rk)
                  {
                  case TR_GPR:
                     opCode = TR::InstOpCode::ldrimmx;
                     break;
                  case TR_FPR:
                     opCode = TR::InstOpCode::vldrimmd;
                     break;
                  default:
                     TR_ASSERT(0, "\nRegister kind not supported in OOL spill\n");
                     break;
                  }

               TR::Instruction *inst = generateTrg1MemInstruction(cg, opCode, currentNode, assignedReg, tempMR, currentInstruction);

               assignedReg->setAssignedRegister(NULL);
               virtReg->setAssignedRegister(NULL);
               assignedReg->setState(TR::RealRegister::Free);

               if (comp->getDebug())
                  cg->traceRegisterAssignment("Generate reload of virt %s due to spillRegIndex dep at inst %p\n", cg->comp()->getDebug()->getName(virtReg), currentInstruction);
               cg->traceRAInstruction(inst);
               }

            if (!(std::find(cg->getSpilledRegisterList()->begin(), cg->getSpilledRegisterList()->end(), virtReg) != cg->getSpilledRegisterList()->end()))
               cg->getSpilledRegisterList()->push_front(virtReg);
            }
         // we also need to free up all locked backing storage if we are exiting the OOL during backwards RA assignment
         else if (currentInstruction->isLabel() && virtReg->getAssignedRealRegister())
            {
            TR::ARM64LabelInstruction *labelInstr = (TR::ARM64LabelInstruction *)currentInstruction;
            TR_BackingStore *location = virtReg->getBackingStorage();
            TR_RegisterKinds rk = virtReg->getKind();
            int32_t dataSize;
            if (labelInstr->getLabelSymbol()->isStartOfColdInstructionStream() && location)
               {
               traceMsg (comp,"\nOOL: Releasing backing storage (%p)\n", location);
               if (rk == TR_GPR)
                  dataSize = TR::Compiler->om.sizeofReferenceAddress();
               else
                  dataSize = 8;
               location->setMaxSpillDepth(0);
               cg->freeSpill(location, dataSize, 0);
               virtReg->setBackingStorage(NULL);
               }
            }
         }
      }

   for (i = 0; i < numberOfRegisters; i++)
      {
      virtReg = _dependencies[i].getRegister();

      if (virtReg->getAssignedRealRegister() != NULL)
         {
         if (_dependencies[i].getRealRegister() == TR::RealRegister::NoReg)
            {
            virtReg->block();
            }
         else
            {
            dependentRegNum = toRealRegister(virtReg->getAssignedRealRegister())->getRegisterNumber();
            for (j = 0; j < numberOfRegisters; j++)
               {
               if (dependentRegNum == _dependencies[j].getRealRegister())
                  {
                  virtReg->block();
                  break;
                  }
               }
            }
         }
      }

   do
      {
      changed = false;
      for (i = 0; i < numberOfRegisters; i++)
         {
         virtReg = _dependencies[i].getRegister();
         dependentRegNum = _dependencies[i].getRealRegister();
         dependentRealReg = machine->getRealRegister(dependentRegNum);

         if (dependentRegNum != TR::RealRegister::NoReg &&
             dependentRegNum != TR::RealRegister::SpilledReg &&
             dependentRealReg->getState() == TR::RealRegister::Free)
            {
            machine->coerceRegisterAssignment(currentInstruction, virtReg, dependentRegNum);
            virtReg->block();
            changed = true;
            }
         }
      } while (changed == true);

   do
      {
      changed = false;
      for (i = 0; i < numberOfRegisters; i++)
         {
         virtReg = _dependencies[i].getRegister();
         assignedRegister = NULL;
         if (virtReg->getAssignedRealRegister() != NULL)
            {
            assignedRegister = toRealRegister(virtReg->getAssignedRealRegister());
            }
         dependentRegNum = _dependencies[i].getRealRegister();
         dependentRealReg = machine->getRealRegister(dependentRegNum);
         if (dependentRegNum != TR::RealRegister::NoReg &&
             dependentRegNum != TR::RealRegister::SpilledReg &&
             dependentRealReg != assignedRegister)
            {
            machine->coerceRegisterAssignment(currentInstruction, virtReg, dependentRegNum);
            virtReg->block();
            changed = true;
            }
         }
      } while (changed == true);

   for (i = 0; i < numberOfRegisters; i++)
      {
      if (_dependencies[i].getRealRegister() == TR::RealRegister::NoReg)
         {
         TR::RealRegister *realOne;

         virtReg = _dependencies[i].getRegister();
         realOne = virtReg->getAssignedRealRegister();
         if (realOne == NULL)
            {
            if (virtReg->getTotalUseCount() == virtReg->getFutureUseCount())
               {
               if ((assignedRegister = machine->findBestFreeRegister(virtReg->getKind(), true)) == NULL)
                  {
                  assignedRegister = machine->freeBestRegister(currentInstruction, virtReg, NULL);
                  }
               }
            else
               {
               assignedRegister = machine->reverseSpillState(currentInstruction, virtReg, NULL);
               }
            virtReg->setAssignedRegister(assignedRegister);
            assignedRegister->setAssignedRegister(virtReg);
            assignedRegister->setState(TR::RealRegister::Assigned);
            virtReg->block();
            }
         }
      }

   unblockRegisters(numberOfRegisters);
   for (i = 0; i < numberOfRegisters; i++)
      {
      TR::Register *dependentRegister = getRegisterDependency(i)->getRegister();
      dependentRegNum = getRegisterDependency(i)->getRealRegister();
      if (dependentRegister->getAssignedRegister())
         {
         TR::RealRegister *assignedRegister = dependentRegister->getAssignedRegister()->getRealRegister();

         if (getRegisterDependency(i)->getRealRegister() == TR::RealRegister::NoReg)
            getRegisterDependency(i)->setRealRegister(toRealRegister(assignedRegister)->getRegisterNumber());

         machine->decFutureUseCountAndUnlatch(currentInstruction, dependentRegister);
         }
      else if (dependentRegNum == TR::RealRegister::SpilledReg)
         {
         machine->decFutureUseCountAndUnlatch(currentInstruction, dependentRegister);
         }
      }
   }
