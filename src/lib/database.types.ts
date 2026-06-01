export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.5"
  }
  public: {
    Tables: {
      accounts: {
        Row: {
          account_email: string | null
          created_at: string | null
          entity_name: string
          entity_type: string
          id: string
          notes: string | null
          parent_entity: string | null
          plan: string | null
          service_name: string
          status: string | null
          updated_at: string | null
          url: string | null
        }
        Insert: {
          account_email?: string | null
          created_at?: string | null
          entity_name: string
          entity_type: string
          id?: string
          notes?: string | null
          parent_entity?: string | null
          plan?: string | null
          service_name: string
          status?: string | null
          updated_at?: string | null
          url?: string | null
        }
        Update: {
          account_email?: string | null
          created_at?: string | null
          entity_name?: string
          entity_type?: string
          id?: string
          notes?: string | null
          parent_entity?: string | null
          plan?: string | null
          service_name?: string
          status?: string | null
          updated_at?: string | null
          url?: string | null
        }
        Relationships: []
      }
      allowed_emails: {
        Row: {
          created_at: string | null
          email: string
          note: string | null
        }
        Insert: {
          created_at?: string | null
          email: string
          note?: string | null
        }
        Update: {
          created_at?: string | null
          email?: string
          note?: string | null
        }
        Relationships: []
      }
      bot_alerts_seen: {
        Row: {
          pushed: boolean
          seen_at: string
          urgency: number | null
          url: string
        }
        Insert: {
          pushed?: boolean
          seen_at?: string
          urgency?: number | null
          url: string
        }
        Update: {
          pushed?: boolean
          seen_at?: string
          urgency?: number | null
          url?: string
        }
        Relationships: []
      }
      bot_conversations: {
        Row: {
          created_at: string
          id: string
          last_message_at: string
          telegram_chat_id: number
          telegram_user_id: number
          title: string | null
        }
        Insert: {
          created_at?: string
          id?: string
          last_message_at?: string
          telegram_chat_id: number
          telegram_user_id: number
          title?: string | null
        }
        Update: {
          created_at?: string
          id?: string
          last_message_at?: string
          telegram_chat_id?: number
          telegram_user_id?: number
          title?: string | null
        }
        Relationships: []
      }
      bot_leads: {
        Row: {
          channel: string
          company: string | null
          created_at: string
          id: string
          last_action_at: string
          name: string
          next_action: string | null
          next_action_at: string | null
          notes: string | null
          role: string | null
          source: string | null
          status: string
          telegram_user_id: number
          updated_at: string
        }
        Insert: {
          channel: string
          company?: string | null
          created_at?: string
          id?: string
          last_action_at?: string
          name: string
          next_action?: string | null
          next_action_at?: string | null
          notes?: string | null
          role?: string | null
          source?: string | null
          status?: string
          telegram_user_id: number
          updated_at?: string
        }
        Update: {
          channel?: string
          company?: string | null
          created_at?: string
          id?: string
          last_action_at?: string
          name?: string
          next_action?: string | null
          next_action_at?: string | null
          notes?: string | null
          role?: string | null
          source?: string | null
          status?: string
          telegram_user_id?: number
          updated_at?: string
        }
        Relationships: []
      }
      bot_messages: {
        Row: {
          content: Json
          conversation_id: string
          created_at: string
          id: string
          role: string
          telegram_message_id: number | null
          tool_calls: Json | null
        }
        Insert: {
          content: Json
          conversation_id: string
          created_at?: string
          id?: string
          role: string
          telegram_message_id?: number | null
          tool_calls?: Json | null
        }
        Update: {
          content?: Json
          conversation_id?: string
          created_at?: string
          id?: string
          role?: string
          telegram_message_id?: number | null
          tool_calls?: Json | null
        }
        Relationships: [
          {
            foreignKeyName: "bot_messages_conversation_id_fkey"
            columns: ["conversation_id"]
            isOneToOne: false
            referencedRelation: "bot_conversations"
            referencedColumns: ["id"]
          },
        ]
      }
      bot_news_sent: {
        Row: {
          sent_at: string
          url: string
        }
        Insert: {
          sent_at?: string
          url: string
        }
        Update: {
          sent_at?: string
          url?: string
        }
        Relationships: []
      }
      bot_owner: {
        Row: {
          claimed_at: string
          key: string
          telegram_user_id: number
        }
        Insert: {
          claimed_at?: string
          key: string
          telegram_user_id: number
        }
        Update: {
          claimed_at?: string
          key?: string
          telegram_user_id?: number
        }
        Relationships: []
      }
      bot_scheduled: {
        Row: {
          cancelled: boolean
          created_at: string
          fire_at: string
          id: string
          last_fired_at: string | null
          message: string
          mode: string
          recurrence: string | null
          telegram_chat_id: number
          telegram_user_id: number
        }
        Insert: {
          cancelled?: boolean
          created_at?: string
          fire_at: string
          id?: string
          last_fired_at?: string | null
          message: string
          mode?: string
          recurrence?: string | null
          telegram_chat_id: number
          telegram_user_id: number
        }
        Update: {
          cancelled?: boolean
          created_at?: string
          fire_at?: string
          id?: string
          last_fired_at?: string | null
          message?: string
          mode?: string
          recurrence?: string | null
          telegram_chat_id?: number
          telegram_user_id?: number
        }
        Relationships: []
      }
      bot_seen_linkedin_emails: {
        Row: {
          gmail_message_id: string
          seen_at: string
        }
        Insert: {
          gmail_message_id: string
          seen_at?: string
        }
        Update: {
          gmail_message_id?: string
          seen_at?: string
        }
        Relationships: []
      }
      bot_tasks: {
        Row: {
          created_at: string
          done: boolean
          done_at: string | null
          due_at: string | null
          id: string
          notes: string | null
          telegram_user_id: number
          title: string
        }
        Insert: {
          created_at?: string
          done?: boolean
          done_at?: string | null
          due_at?: string | null
          id?: string
          notes?: string | null
          telegram_user_id: number
          title: string
        }
        Update: {
          created_at?: string
          done?: boolean
          done_at?: string | null
          due_at?: string | null
          id?: string
          notes?: string | null
          telegram_user_id?: number
          title?: string
        }
        Relationships: []
      }
      clients: {
        Row: {
          business_type: string | null
          contact_name: string | null
          created_at: string | null
          current_tools: string | null
          domain: string | null
          email: string | null
          employees_count: string | null
          goal: string | null
          has_domain: boolean | null
          has_examples: boolean | null
          has_logo: boolean | null
          id: string
          intake_completed_at: string | null
          intake_confirmation_error: string | null
          intake_confirmation_sent_at: string | null
          intake_data: Json | null
          intake_sent_at: string | null
          intake_token: string | null
          must_have: string | null
          name: string
          needs_payments: boolean | null
          nice_to_have: string | null
          notes: string | null
          package: string | null
          paid_amount: number | null
          pain_points: Json | null
          phone: string | null
          playbook_progress: Json
          service_type: string | null
          status: string | null
          total_amount: number | null
          updated_at: string | null
          urgency: string | null
          website_url: string | null
          years_in_business: string | null
        }
        Insert: {
          business_type?: string | null
          contact_name?: string | null
          created_at?: string | null
          current_tools?: string | null
          domain?: string | null
          email?: string | null
          employees_count?: string | null
          goal?: string | null
          has_domain?: boolean | null
          has_examples?: boolean | null
          has_logo?: boolean | null
          id?: string
          intake_completed_at?: string | null
          intake_confirmation_error?: string | null
          intake_confirmation_sent_at?: string | null
          intake_data?: Json | null
          intake_sent_at?: string | null
          intake_token?: string | null
          must_have?: string | null
          name: string
          needs_payments?: boolean | null
          nice_to_have?: string | null
          notes?: string | null
          package?: string | null
          paid_amount?: number | null
          pain_points?: Json | null
          phone?: string | null
          playbook_progress?: Json
          service_type?: string | null
          status?: string | null
          total_amount?: number | null
          updated_at?: string | null
          urgency?: string | null
          website_url?: string | null
          years_in_business?: string | null
        }
        Update: {
          business_type?: string | null
          contact_name?: string | null
          created_at?: string | null
          current_tools?: string | null
          domain?: string | null
          email?: string | null
          employees_count?: string | null
          goal?: string | null
          has_domain?: boolean | null
          has_examples?: boolean | null
          has_logo?: boolean | null
          id?: string
          intake_completed_at?: string | null
          intake_confirmation_error?: string | null
          intake_confirmation_sent_at?: string | null
          intake_data?: Json | null
          intake_sent_at?: string | null
          intake_token?: string | null
          must_have?: string | null
          name?: string
          needs_payments?: boolean | null
          nice_to_have?: string | null
          notes?: string | null
          package?: string | null
          paid_amount?: number | null
          pain_points?: Json | null
          phone?: string | null
          playbook_progress?: Json
          service_type?: string | null
          status?: string | null
          total_amount?: number | null
          updated_at?: string | null
          urgency?: string | null
          website_url?: string | null
          years_in_business?: string | null
        }
        Relationships: []
      }
      cost_items: {
        Row: {
          active: boolean | null
          cons: string | null
          cost_ils: number | null
          cost_usd: number | null
          created_at: string | null
          display_order: number | null
          free_alternative: string | null
          id: string
          is_free: boolean | null
          name: string
          name_en: string | null
          notes: string | null
          pros: string | null
          type: string
        }
        Insert: {
          active?: boolean | null
          cons?: string | null
          cost_ils?: number | null
          cost_usd?: number | null
          created_at?: string | null
          display_order?: number | null
          free_alternative?: string | null
          id?: string
          is_free?: boolean | null
          name: string
          name_en?: string | null
          notes?: string | null
          pros?: string | null
          type: string
        }
        Update: {
          active?: boolean | null
          cons?: string | null
          cost_ils?: number | null
          cost_usd?: number | null
          created_at?: string | null
          display_order?: number | null
          free_alternative?: string | null
          id?: string
          is_free?: boolean | null
          name?: string
          name_en?: string | null
          notes?: string | null
          pros?: string | null
          type?: string
        }
        Relationships: []
      }
      expenses: {
        Row: {
          amount: number
          category: string | null
          created_at: string | null
          currency: string | null
          frequency: string | null
          id: string
          next_charge_date: string | null
          notes: string | null
          service_name: string
          status: string | null
          updated_at: string | null
        }
        Insert: {
          amount?: number
          category?: string | null
          created_at?: string | null
          currency?: string | null
          frequency?: string | null
          id?: string
          next_charge_date?: string | null
          notes?: string | null
          service_name: string
          status?: string | null
          updated_at?: string | null
        }
        Update: {
          amount?: number
          category?: string | null
          created_at?: string | null
          currency?: string | null
          frequency?: string | null
          id?: string
          next_charge_date?: string | null
          notes?: string | null
          service_name?: string
          status?: string | null
          updated_at?: string | null
        }
        Relationships: []
      }
      files: {
        Row: {
          category: string | null
          client_id: string | null
          file_name: string
          file_type: string | null
          id: string
          lead_id: string | null
          size_bytes: number | null
          storage_path: string
          uploaded_at: string | null
        }
        Insert: {
          category?: string | null
          client_id?: string | null
          file_name: string
          file_type?: string | null
          id?: string
          lead_id?: string | null
          size_bytes?: number | null
          storage_path: string
          uploaded_at?: string | null
        }
        Update: {
          category?: string | null
          client_id?: string | null
          file_name?: string
          file_type?: string | null
          id?: string
          lead_id?: string | null
          size_bytes?: number | null
          storage_path?: string
          uploaded_at?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "files_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "files_lead_id_fkey"
            columns: ["lead_id"]
            isOneToOne: false
            referencedRelation: "leads"
            referencedColumns: ["id"]
          },
        ]
      }
      invoices: {
        Row: {
          client_email_snapshot: string | null
          client_id: string | null
          client_name_snapshot: string | null
          created_at: string | null
          due_date: string | null
          id: string
          invoice_number: string
          issued_at: string | null
          items: Json | null
          notes: string | null
          paid_at: string | null
          payment_id: string | null
          status: string | null
          subtotal: number
          token: string
          token_expires_at: string | null
          total: number
          vat_amount: number | null
          vat_rate: number | null
        }
        Insert: {
          client_email_snapshot?: string | null
          client_id?: string | null
          client_name_snapshot?: string | null
          created_at?: string | null
          due_date?: string | null
          id?: string
          invoice_number?: string
          issued_at?: string | null
          items?: Json | null
          notes?: string | null
          paid_at?: string | null
          payment_id?: string | null
          status?: string | null
          subtotal?: number
          token?: string
          token_expires_at?: string | null
          total?: number
          vat_amount?: number | null
          vat_rate?: number | null
        }
        Update: {
          client_email_snapshot?: string | null
          client_id?: string | null
          client_name_snapshot?: string | null
          created_at?: string | null
          due_date?: string | null
          id?: string
          invoice_number?: string
          issued_at?: string | null
          items?: Json | null
          notes?: string | null
          paid_at?: string | null
          payment_id?: string | null
          status?: string | null
          subtotal?: number
          token?: string
          token_expires_at?: string | null
          total?: number
          vat_amount?: number | null
          vat_rate?: number | null
        }
        Relationships: [
          {
            foreignKeyName: "invoices_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "invoices_payment_id_fkey"
            columns: ["payment_id"]
            isOneToOne: false
            referencedRelation: "payments"
            referencedColumns: ["id"]
          },
        ]
      }
      leads: {
        Row: {
          budget: string | null
          business_name: string
          business_type: string | null
          contact_name: string | null
          converted_to_client_id: string | null
          created_at: string | null
          domain: string | null
          email: string | null
          goal: string | null
          has_domain: boolean | null
          has_logo: boolean | null
          id: string
          intake_confirmation_error: string | null
          intake_confirmation_sent_at: string | null
          intake_token: string | null
          is_draft: boolean
          must_have: string | null
          needs_payments: boolean | null
          nice_to_have: string | null
          pain_points: Json | null
          phone: string | null
          raw_data: Json | null
          service_type: string | null
          urgency: string | null
        }
        Insert: {
          budget?: string | null
          business_name: string
          business_type?: string | null
          contact_name?: string | null
          converted_to_client_id?: string | null
          created_at?: string | null
          domain?: string | null
          email?: string | null
          goal?: string | null
          has_domain?: boolean | null
          has_logo?: boolean | null
          id?: string
          intake_confirmation_error?: string | null
          intake_confirmation_sent_at?: string | null
          intake_token?: string | null
          is_draft?: boolean
          must_have?: string | null
          needs_payments?: boolean | null
          nice_to_have?: string | null
          pain_points?: Json | null
          phone?: string | null
          raw_data?: Json | null
          service_type?: string | null
          urgency?: string | null
        }
        Update: {
          budget?: string | null
          business_name?: string
          business_type?: string | null
          contact_name?: string | null
          converted_to_client_id?: string | null
          created_at?: string | null
          domain?: string | null
          email?: string | null
          goal?: string | null
          has_domain?: boolean | null
          has_logo?: boolean | null
          id?: string
          intake_confirmation_error?: string | null
          intake_confirmation_sent_at?: string | null
          intake_token?: string | null
          is_draft?: boolean
          must_have?: string | null
          needs_payments?: boolean | null
          nice_to_have?: string | null
          pain_points?: Json | null
          phone?: string | null
          raw_data?: Json | null
          service_type?: string | null
          urgency?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "leads_converted_to_client_id_fkey"
            columns: ["converted_to_client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
        ]
      }
      login_attempts: {
        Row: {
          attempted_at: string
          email: string
          id: number
          success: boolean
        }
        Insert: {
          attempted_at?: string
          email: string
          id?: never
          success?: boolean
        }
        Update: {
          attempted_at?: string
          email?: string
          id?: never
          success?: boolean
        }
        Relationships: []
      }
      notes: {
        Row: {
          client_id: string | null
          content: string
          created_at: string | null
          id: string
        }
        Insert: {
          client_id?: string | null
          content: string
          created_at?: string | null
          id?: string
        }
        Update: {
          client_id?: string | null
          content?: string
          created_at?: string | null
          id?: string
        }
        Relationships: [
          {
            foreignKeyName: "notes_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
        ]
      }
      packages: {
        Row: {
          active: boolean | null
          category: string | null
          code: string
          created_at: string | null
          description: string | null
          display_order: number | null
          featured: boolean | null
          features: Json | null
          id: string
          label: string
          maint_price: number | null
          price: number
          tagline: string | null
          timeline_weeks: number | null
          unit_label: string | null
          updated_at: string | null
        }
        Insert: {
          active?: boolean | null
          category?: string | null
          code: string
          created_at?: string | null
          description?: string | null
          display_order?: number | null
          featured?: boolean | null
          features?: Json | null
          id?: string
          label: string
          maint_price?: number | null
          price?: number
          tagline?: string | null
          timeline_weeks?: number | null
          unit_label?: string | null
          updated_at?: string | null
        }
        Update: {
          active?: boolean | null
          category?: string | null
          code?: string
          created_at?: string | null
          description?: string | null
          display_order?: number | null
          featured?: boolean | null
          features?: Json | null
          id?: string
          label?: string
          maint_price?: number | null
          price?: number
          tagline?: string | null
          timeline_weeks?: number | null
          unit_label?: string | null
          updated_at?: string | null
        }
        Relationships: []
      }
      passkey_challenges: {
        Row: {
          challenge: string
          created_at: string
          purpose: string
          user_id: string | null
        }
        Insert: {
          challenge: string
          created_at?: string
          purpose: string
          user_id?: string | null
        }
        Update: {
          challenge?: string
          created_at?: string
          purpose?: string
          user_id?: string | null
        }
        Relationships: []
      }
      passkeys: {
        Row: {
          aaguid: string | null
          backup_eligible: boolean
          backup_state: boolean
          counter: number
          created_at: string
          credential_id: string
          device_name: string | null
          id: string
          last_used_at: string | null
          public_key: string
          transports: string[]
          user_id: string
        }
        Insert: {
          aaguid?: string | null
          backup_eligible?: boolean
          backup_state?: boolean
          counter?: number
          created_at?: string
          credential_id: string
          device_name?: string | null
          id?: string
          last_used_at?: string | null
          public_key: string
          transports?: string[]
          user_id: string
        }
        Update: {
          aaguid?: string | null
          backup_eligible?: boolean
          backup_state?: boolean
          counter?: number
          created_at?: string
          credential_id?: string
          device_name?: string | null
          id?: string
          last_used_at?: string | null
          public_key?: string
          transports?: string[]
          user_id?: string
        }
        Relationships: []
      }
      payments: {
        Row: {
          amount: number
          client_id: string | null
          due_date: string | null
          id: string
          paid_at: string | null
          phase: string | null
          project_id: string | null
          status: string | null
        }
        Insert: {
          amount: number
          client_id?: string | null
          due_date?: string | null
          id?: string
          paid_at?: string | null
          phase?: string | null
          project_id?: string | null
          status?: string | null
        }
        Update: {
          amount?: number
          client_id?: string | null
          due_date?: string | null
          id?: string
          paid_at?: string | null
          phase?: string | null
          project_id?: string | null
          status?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "payments_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "payments_project_id_fkey"
            columns: ["project_id"]
            isOneToOne: false
            referencedRelation: "projects"
            referencedColumns: ["id"]
          },
        ]
      }
      projects: {
        Row: {
          client_id: string | null
          created_at: string | null
          id: string
          name: string
          progress: number | null
          stage: string | null
          start_date: string | null
          target_date: string | null
        }
        Insert: {
          client_id?: string | null
          created_at?: string | null
          id?: string
          name: string
          progress?: number | null
          stage?: string | null
          start_date?: string | null
          target_date?: string | null
        }
        Update: {
          client_id?: string | null
          created_at?: string | null
          id?: string
          name?: string
          progress?: number | null
          stage?: string | null
          start_date?: string | null
          target_date?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "projects_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
        ]
      }
      proposals: {
        Row: {
          accepted_at: string | null
          client_id: string | null
          created_at: string | null
          id: string
          package: string | null
          payment_schedule: Json | null
          scope_items: Json | null
          signature_data: string | null
          signer_name: string | null
          status: string | null
          terms: string | null
          timeline_weeks: number | null
          title: string
          token: string
          token_expires_at: string | null
          total_amount: number
          updated_at: string | null
          valid_until: string | null
        }
        Insert: {
          accepted_at?: string | null
          client_id?: string | null
          created_at?: string | null
          id?: string
          package?: string | null
          payment_schedule?: Json | null
          scope_items?: Json | null
          signature_data?: string | null
          signer_name?: string | null
          status?: string | null
          terms?: string | null
          timeline_weeks?: number | null
          title: string
          token?: string
          token_expires_at?: string | null
          total_amount?: number
          updated_at?: string | null
          valid_until?: string | null
        }
        Update: {
          accepted_at?: string | null
          client_id?: string | null
          created_at?: string | null
          id?: string
          package?: string | null
          payment_schedule?: Json | null
          scope_items?: Json | null
          signature_data?: string | null
          signer_name?: string | null
          status?: string | null
          terms?: string | null
          timeline_weeks?: number | null
          title?: string
          token?: string
          token_expires_at?: string | null
          total_amount?: number
          updated_at?: string | null
          valid_until?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "proposals_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
        ]
      }
      tasks: {
        Row: {
          client_id: string | null
          completed_at: string | null
          created_at: string | null
          description: string | null
          due_date: string | null
          id: string
          priority: string | null
          project_id: string | null
          status: string | null
          title: string
        }
        Insert: {
          client_id?: string | null
          completed_at?: string | null
          created_at?: string | null
          description?: string | null
          due_date?: string | null
          id?: string
          priority?: string | null
          project_id?: string | null
          status?: string | null
          title: string
        }
        Update: {
          client_id?: string | null
          completed_at?: string | null
          created_at?: string | null
          description?: string | null
          due_date?: string | null
          id?: string
          priority?: string | null
          project_id?: string | null
          status?: string | null
          title?: string
        }
        Relationships: [
          {
            foreignKeyName: "tasks_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "tasks_project_id_fkey"
            columns: ["project_id"]
            isOneToOne: false
            referencedRelation: "projects"
            referencedColumns: ["id"]
          },
        ]
      }
      time_entries: {
        Row: {
          client_id: string | null
          created_at: string | null
          duration_seconds: number | null
          ended_at: string | null
          id: string
          note: string | null
          started_at: string
          task_id: string | null
        }
        Insert: {
          client_id?: string | null
          created_at?: string | null
          duration_seconds?: number | null
          ended_at?: string | null
          id?: string
          note?: string | null
          started_at: string
          task_id?: string | null
        }
        Update: {
          client_id?: string | null
          created_at?: string | null
          duration_seconds?: number | null
          ended_at?: string | null
          id?: string
          note?: string | null
          started_at?: string
          task_id?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "time_entries_client_id_fkey"
            columns: ["client_id"]
            isOneToOne: false
            referencedRelation: "clients"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "time_entries_task_id_fkey"
            columns: ["task_id"]
            isOneToOne: false
            referencedRelation: "tasks"
            referencedColumns: ["id"]
          },
        ]
      }
      vs_audit_log: {
        Row: {
          created_at: string
          event_type: string
          id: number
          ip_hash: string | null
          metadata: Json
          path: string | null
          scan_outcome: string | null
          scanned_url: string | null
          session_id: string | null
          user_agent: string | null
          user_id: string | null
          vibe_score: number | null
          waf_vendor: string | null
        }
        Insert: {
          created_at?: string
          event_type: string
          id?: number
          ip_hash?: string | null
          metadata?: Json
          path?: string | null
          scan_outcome?: string | null
          scanned_url?: string | null
          session_id?: string | null
          user_agent?: string | null
          user_id?: string | null
          vibe_score?: number | null
          waf_vendor?: string | null
        }
        Update: {
          created_at?: string
          event_type?: string
          id?: number
          ip_hash?: string | null
          metadata?: Json
          path?: string | null
          scan_outcome?: string | null
          scanned_url?: string | null
          session_id?: string | null
          user_agent?: string | null
          user_id?: string | null
          vibe_score?: number | null
          waf_vendor?: string | null
        }
        Relationships: []
      }
      vs_oast_hits: {
        Row: {
          hit_at: string
          id: number
          remote_addr: string | null
          token: string
          user_agent: string | null
        }
        Insert: {
          hit_at?: string
          id?: never
          remote_addr?: string | null
          token: string
          user_agent?: string | null
        }
        Update: {
          hit_at?: string
          id?: never
          remote_addr?: string | null
          token?: string
          user_agent?: string | null
        }
        Relationships: []
      }
      vs_oauth_states: {
        Row: {
          created_at: string
          domain: string
          expires_at: string
          provider: string
          state: string
          uuid: string
        }
        Insert: {
          created_at?: string
          domain: string
          expires_at?: string
          provider: string
          state: string
          uuid: string
        }
        Update: {
          created_at?: string
          domain?: string
          expires_at?: string
          provider?: string
          state?: string
          uuid?: string
        }
        Relationships: []
      }
      vs_scan_log: {
        Row: {
          country: string | null
          hostname: string
          id: number
          scan_outcome: string | null
          scanned_at: string
          stealth_retry_attempted: boolean | null
          stealth_retry_succeeded: boolean | null
          top_finding_id: string | null
          top_finding_severity: string | null
          top_finding_title: string | null
          vibe_score: number
          waf_blocked: boolean | null
          waf_vendor: string | null
        }
        Insert: {
          country?: string | null
          hostname: string
          id?: number
          scan_outcome?: string | null
          scanned_at?: string
          stealth_retry_attempted?: boolean | null
          stealth_retry_succeeded?: boolean | null
          top_finding_id?: string | null
          top_finding_severity?: string | null
          top_finding_title?: string | null
          vibe_score: number
          waf_blocked?: boolean | null
          waf_vendor?: string | null
        }
        Update: {
          country?: string | null
          hostname?: string
          id?: number
          scan_outcome?: string | null
          scanned_at?: string
          stealth_retry_attempted?: boolean | null
          stealth_retry_succeeded?: boolean | null
          top_finding_id?: string | null
          top_finding_severity?: string | null
          top_finding_title?: string | null
          vibe_score?: number
          waf_blocked?: boolean | null
          waf_vendor?: string | null
        }
        Relationships: []
      }
      vs_stage2_collections: {
        Row: {
          collected_at: string
          data: Json
          expires_at: string
          url: string
          user_agent: string | null
          uuid: string
        }
        Insert: {
          collected_at?: string
          data: Json
          expires_at?: string
          url: string
          user_agent?: string | null
          uuid: string
        }
        Update: {
          collected_at?: string
          data?: Json
          expires_at?: string
          url?: string
          user_agent?: string | null
          uuid?: string
        }
        Relationships: []
      }
      vs_verified_domains: {
        Row: {
          domain: string
          expires_at: string
          method: string
          scan_count: number
          user_agent: string | null
          uuid: string
          verified_at: string
        }
        Insert: {
          domain: string
          expires_at?: string
          method: string
          scan_count?: number
          user_agent?: string | null
          uuid: string
          verified_at?: string
        }
        Update: {
          domain?: string
          expires_at?: string
          method?: string
          scan_count?: number
          user_agent?: string | null
          uuid?: string
          verified_at?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      check_login_lockout: {
        Args: {
          p_email: string
          p_max_fails?: number
          p_window_minutes?: number
        }
        Returns: Json
      }
      generate_intake_token: { Args: { p_client_id: string }; Returns: string }
      get_intake_client: { Args: { p_token: string }; Returns: Json }
      get_intake_email_target: { Args: { p_token: string }; Returns: Json }
      is_allowed_user: { Args: never; Returns: boolean }
      is_valid_intake_token: { Args: { p_token: string }; Returns: boolean }
      record_intake_email_event: {
        Args: {
          p_error?: string
          p_kind: string
          p_success: boolean
          p_token: string
        }
        Returns: undefined
      }
      record_login_attempt: {
        Args: {
          p_email: string
          p_max_fails?: number
          p_success: boolean
          p_window_minutes?: number
        }
        Returns: Json
      }
      start_anonymous_intake: { Args: never; Returns: string }
      submit_anonymous_intake: {
        Args: { p_data: Json; p_token: string }
        Returns: string
      }
      submit_intake: {
        Args: { p_data: Json; p_token: string }
        Returns: string
      }
      vs_audit_log_purge_old: { Args: never; Returns: undefined }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
