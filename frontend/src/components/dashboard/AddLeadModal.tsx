import React from 'react';
import { useForm } from 'react-hook-form';
import { X } from 'lucide-react';
import { useDashboardStore } from '@/stores/dashboardStore';
import toast from 'react-hot-toast';

interface LeadFormData {
  name: string;
  email: string;
  source: string;
  value: number;
}

interface AddLeadModalProps {
  isOpen: boolean;
  onClose: () => void;
}

/**
 * Modal for adding new leads with React Hook Form validation
 */
export const AddLeadModal: React.FC<AddLeadModalProps> = ({
  isOpen,
  onClose,
}) => {
  const { addLead } = useDashboardStore();
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<LeadFormData>();

  const onSubmit = async (data: LeadFormData) => {
    try {
      await addLead({
        ...data,
        status: 'New',
        value: Number(data.value),
      });
      toast.success('Lead added successfully!');
      reset();
      onClose();
    } catch (error) {
      toast.error('Failed to add lead');
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-999999 flex items-center justify-center bg-black bg-opacity-50">
      <div className="relative w-full max-w-md rounded-lg bg-white p-8 shadow-lg dark:bg-boxdark">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-bodydark hover:text-black dark:hover:text-white"
        >
          <X className="h-6 w-6" />
        </button>

        {/* Title */}
        <h3 className="mb-6 text-2xl font-bold text-black dark:text-white">
          Add New Lead
        </h3>

        {/* Form */}
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          {/* Name */}
          <div>
            <label className="mb-2.5 block text-black dark:text-white">
              Name <span className="text-meta-1">*</span>
            </label>
            <input
              type="text"
              {...register('name', { required: 'Name is required' })}
              className="w-full rounded border-[1.5px] border-stroke bg-transparent px-5 py-3 outline-none transition focus:border-primary dark:border-form-strokedark dark:bg-form-input dark:focus:border-primary"
            />
            {errors.name && (
              <p className="mt-1 text-sm text-meta-1">{errors.name.message}</p>
            )}
          </div>

          {/* Email */}
          <div>
            <label className="mb-2.5 block text-black dark:text-white">
              Email <span className="text-meta-1">*</span>
            </label>
            <input
              type="email"
              {...register('email', {
                required: 'Email is required',
                pattern: {
                  value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                  message: 'Invalid email address',
                },
              })}
              className="w-full rounded border-[1.5px] border-stroke bg-transparent px-5 py-3 outline-none transition focus:border-primary dark:border-form-strokedark dark:bg-form-input dark:focus:border-primary"
            />
            {errors.email && (
              <p className="mt-1 text-sm text-meta-1">
                {errors.email.message}
              </p>
            )}
          </div>

          {/* Source */}
          <div>
            <label className="mb-2.5 block text-black dark:text-white">
              Source <span className="text-meta-1">*</span>
            </label>
            <select
              {...register('source', { required: 'Source is required' })}
              className="w-full rounded border-[1.5px] border-stroke bg-transparent px-5 py-3 outline-none transition focus:border-primary dark:border-form-strokedark dark:bg-form-input dark:focus:border-primary"
            >
              <option value="">Select source</option>
              <option value="Website">Website</option>
              <option value="Referral">Referral</option>
              <option value="LinkedIn">LinkedIn</option>
              <option value="Cold Email">Cold Email</option>
              <option value="Other">Other</option>
            </select>
            {errors.source && (
              <p className="mt-1 text-sm text-meta-1">
                {errors.source.message}
              </p>
            )}
          </div>

          {/* Value */}
          <div>
            <label className="mb-2.5 block text-black dark:text-white">
              Estimated Value ($) <span className="text-meta-1">*</span>
            </label>
            <input
              type="number"
              {...register('value', {
                required: 'Value is required',
                min: { value: 0, message: 'Value must be positive' },
              })}
              className="w-full rounded border-[1.5px] border-stroke bg-transparent px-5 py-3 outline-none transition focus:border-primary dark:border-form-strokedark dark:bg-form-input dark:focus:border-primary"
            />
            {errors.value && (
              <p className="mt-1 text-sm text-meta-1">
                {errors.value.message}
              </p>
            )}
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full rounded bg-brand-primary-600 p-3 font-medium text-white transition hover:bg-brand-primary-700 disabled:opacity-50"
          >
            {isSubmitting ? 'Adding...' : 'Add Lead'}
          </button>
        </form>
      </div>
    </div>
  );
};
